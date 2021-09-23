#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
import json
import logging
from encodings.base64_codec import base64_decode
from json import JSONDecodeError
from urllib.parse import urlencode
from uuid import uuid4

from flask import Blueprint, redirect, request, jsonify, current_app, render_template, session

from application.database import db
from application.fhir_client import fhir_client
from application.irma_client import irma_client
from application.oauth_server.model import Oauth2Session, Oauth2Token
from application.oauth_server.service import token_service, oauth2_client_credentials_service, smart_hti_on_fhir_service

DEFAULT_SCOPE = '*/write'
logger = logging.getLogger('oauth_views')
logger.setLevel(logging.DEBUG)


def create_blueprint() -> Blueprint:
    blueprint = Blueprint(__name__.split('.')[-2], __name__)

    @blueprint.errorhandler(AssertionError)
    def handle_assertionerror(e):
        print(f'Catching assertion error {e}, returning 400')
        return 'Bad Request, assertion failed', 400

    @blueprint.route('/oauth2/authorize')
    def authorize():
        oauth_session = Oauth2Session()

        oauth_session.type = _get_session_type()
        oauth_session.scope = request.values.get('scope')
        oauth_session.response_type = request.values.get('response_type')
        oauth_session.client_id = request.values.get('client_id')
        oauth_session.redirect_uri = request.values.get('redirect_uri')
        oauth_session.state = request.values.get('state')
        oauth_session.launch = request.values.get('launch', None)
        oauth_session.aud = request.values.get('aud', None)
        oauth_session.code = str(uuid4())

        if 'username' in session:  # Fixme:
            username = session['username']
            _update_fhir_user(oauth_session, username)

        db.session.add(oauth_session)
        db.session.commit()

        return route_from_authorise(oauth_session)

    def _get_session_type():
        aud = request.values.get('aud', None)
        launch = request.values.get('launch', None)
        type = 'smart_backend' if aud is None and launch is None else 'smart_hti_on_fhir'
        return type

    @blueprint.route('/oauth2/restart')
    def restart():
        oauth_session_id = request.values['session']
        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()
        oauth_session.consent = False
        _update_fhir_user(oauth_session, None)
        oauth_session.user_fhir_reference = None
        db.session.add(oauth_session)
        db.session.commit()
        return route_from_authorise(oauth_session)

    @blueprint.route('/oauth2/consent', methods=['GET'])
    def consent_get():
        oauth_session_id = request.values['session']
        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()
        scopes = oauth_session.scope.split(' ')
        keep = 'username' in session
        return render_template('oauth2_consent.html', username=oauth_session.username, session=oauth_session_id,
                               scopes=scopes, client_id=oauth_session.client_id, keep=keep)

    @blueprint.route('/oauth2/consent', methods=['POST'])
    def consent_post():
        oauth_session_id = request.values['session']
        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()

        oauth_session.scope = ' '.join(request.form.getlist('scope'))
        oauth_session.consent = True

        if 'keep' in request.values:
            session['username'] = oauth_session.username
        else:
            session['username'] = None

        db.session.add(oauth_session)
        db.session.commit()

        return redirect(
            f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')

    @blueprint.route('/oauth2/token', methods=['POST', 'GET'])
    def token():
        grant_type = request.values.get('grant_type')

        if grant_type == 'authorization_code':
            return token_authorization_code()
        if grant_type == 'refresh_token':
            return token_refresh_token()
        if grant_type == 'client_credentials':
            return token_client_credentials()
        else:
            return 'Bad Request', 400

    @blueprint.route('/oauth2/irma-auth')
    def irma_auth():
        token = request.values['token']
        oauth_session_id = request.values['session']

        username = irma_client.validate_token(token)

        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()
        _update_fhir_user(oauth_session, username)

        db.session.commit()

        if not oauth_session.consent:
            return redirect('/oauth2/consent?' + urlencode({'session': oauth_session.id}))
        else:
            return redirect(
                f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')

    def route_from_authorise(oauth_session):
        # This is a SMART HTI on FHIR launch
        if oauth_session.type == 'smart_hti_on_fhir':
            assert current_app.config['FHIR_CLIENT_SERVERURL'] == oauth_session.aud
            if smart_hti_on_fhir_service.validate_launch_token(oauth_session.launch):
                return redirect(
                    f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')
            else:
                return 'Bad Request, invalid launch token', 400
        # If the username is set, the user is identified.
        if oauth_session.username is None:
            return redirect(irma_client.get_redirect_url({'session': oauth_session.id}))
        if not oauth_session.consent:
            return redirect('/oauth2/consent?' + urlencode({'session': oauth_session.id}))
        else:
            return redirect(
                f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')

    def token_refresh_token():
        refresh_token = request.values.get('refresh_token')

        scope = request.values.get('scope', DEFAULT_SCOPE)
        oauth2_token: Oauth2Token = Oauth2Token.query.filter_by(refresh_token=refresh_token).first()
        if oauth2_token is None:
            print(f'Cannot locate Oauth2Token with refresh token {refresh_token}')
            return 'Bad Request, invalid token', 400

        oauth2_session = None
        if oauth2_token.session_id:
            oauth2_session = Oauth2Session.query.filter_by(id=oauth2_token.session_id).first()
            if oauth2_session is None:
                return 'Bad Request, invalid session', 400

        if not scope == oauth2_token.scope:
            print(f'Invalid scope {scope}, expecting {oauth2_token.scope}.')
            return 'Bad Request, invalid scope', 400

        oauth2_token.id_token = token_service.get_id_token(oauth2_token)
        oauth2_token.access_token = token_service.get_access_token(oauth2_token, scope)
        if oauth2_token.refresh_token is None:
            oauth2_token.refresh_token = token_service.get_refresh_token()
        db.session.add(oauth2_token)
        json = oauth2_token_task_to_json(oauth2_token, oauth2_session)
        db.session.commit()
        return jsonify(json)

    def oauth2_token_task_to_json(oauth2_token: Oauth2Token, oauth2_session: Oauth2Session = None):
        rv = {'access_token': oauth2_token.access_token,
              "token_type": "Bearer",
              "refresh_token": oauth2_token.refresh_token,
              "expires_in": current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN']}

        if oauth2_token.id_token:
            rv['id_token'] = oauth2_token.id_token

        body = _get_launch_token_body(oauth2_session)
        if 'sub' in body:
            subject: str = body['sub']
            if subject.startswith('Patient/'):
                rv['patient'] = subject
            if subject.startswith('Practitioner/'):
                rv['practitioner'] = subject
            if subject.startswith('RelatedPerson/'):
                rv['relatedperson'] = subject
        if 'task' in body:
            task = body['task']
            if 'id' in task:
                rv['task'] = f'Task/{task["id"]}'
            if 'instantiatesCanonical' in task:
                rv['activity'] = task['instantiatesCanonical']  ## TODO: chop whole URL?

        return rv

    def token_authorization_code():
        code = request.values.get('code')
        redirect_uri = request.values.get('redirect_uri')
        ## TODO: The token request must be autheticated.
        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(code=code).first()
        assert redirect_uri == oauth2_session.redirect_uri
        if oauth2_session.type == 'smart_hti_on_fhir':
            return _oauth_token_smart_hti_on_fhir(oauth2_session)
        elif oauth2_session.type == 'smart_backend':
            return _oauth_token_smart_backend_services(oauth2_session)

    def _oauth_token_smart_hti_on_fhir(oauth2_session):
        oauth2_token = Oauth2Token()
        # oauth2_token.email = oauth2_session.email
        # oauth2_token.name_family = oauth2_session.name_family
        # oauth2_token.name_given = oauth2_session.name_given
        # oauth2_token.subject = oauth2_session.user_fhir_reference
        oauth2_token.client_id = oauth2_session.client_id
        body = _get_launch_token_body(oauth2_session)

        oauth2_token.subject = body['sub']

        oauth2_token.scope = oauth2_session.scope
        oauth2_token.client_id = oauth2_session.client_id
        oauth2_token.id_token = token_service.get_id_token(oauth2_token)
        ## NOOP:
        oauth2_token.access_token = 'NOOP'
        ## NOOP:
        oauth2_token.refresh_token = 'NOOP'
        oauth2_token.session_id = oauth2_session.id
        db.session.add(oauth2_token)
        db.session.commit()
        return jsonify(oauth2_token_task_to_json(oauth2_token, oauth2_session))

    def _get_launch_token_body(oauth2_session):
        body = {}
        if oauth2_session and oauth2_session.launch and oauth2_session.launch.count('.') == 2:
            try:
                body_encoded = oauth2_session.launch.split('.')[1]
                body = json.loads(base64_decode(body_encoded.encode('ascii') + b'===')[0].decode('ascii'))
            except JSONDecodeError:
                print(f'Failed to process token: {oauth2_session.launch}')
        return body

    def _oauth_token_smart_backend_services(oauth2_session):
        oauth2_token = Oauth2Token()
        oauth2_token.email = oauth2_session.email
        oauth2_token.name_family = oauth2_session.name_family
        oauth2_token.name_given = oauth2_session.name_given
        oauth2_token.subject = oauth2_session.user_fhir_reference
        oauth2_token.scope = oauth2_session.scope
        oauth2_token.client_id = oauth2_session.client_id
        oauth2_token.id_token = token_service.get_id_token(oauth2_token)
        oauth2_token.access_token = token_service.get_access_token(oauth2_token, oauth2_session.scope)
        oauth2_token.refresh_token = token_service.get_refresh_token()
        oauth2_token.session_id = oauth2_session.id
        db.session.add(oauth2_token)
        db.session.commit()
        return jsonify(oauth2_token_task_to_json(oauth2_token, oauth2_session))

    # private_key_jwt flow https://hl7.org/fhir/uv/bulkdata/authorization/index.html#obtaining-an-access-token
    def token_client_credentials():
        client_assertion_type = request.form.get('client_assertion_type')
        # Check if the client_assertion_type is set correctly.
        if client_assertion_type == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer':
            jwt = oauth2_client_credentials_service.verify_and_get_token()

            if jwt:
                logger.info("Generating OAuth access token for issuer [%s]", jwt['iss'])
                oauth2_token = Oauth2Token()
                oauth2_token.client_id = jwt['iss']
                oauth2_token.scope = request.form.get('scope')  # TODO: Verify if scope is allowed?
                oauth2_token.access_token = token_service.get_access_token(oauth2_token, request.form.get('scope'))
                oauth2_token.refresh_token = token_service.get_refresh_token()
                db.session.add(oauth2_token)
                db.session.commit()
                return jsonify(oauth2_token_task_to_json(oauth2_token))

        logger.info("Invalid client credential request - returning access denied")
        return 'Access Denied', 401

    def _update_fhir_user(oauth_session, username):
        if username is None:
            oauth_session.username = None
            oauth_session.email = None
            oauth_session.name_family = None
            oauth_session.name_given = None
        else:
            fhir_user = fhir_client.get_or_create_fhir_user(username)
            oauth_session.username = username
            oauth_session.email = username
            oauth_session.user_fhir_reference = f"{fhir_user['resourceType']}/{fhir_user['id']}"
            if 'name' in fhir_user and len(fhir_user['name']) > 0:
                oauth_session.name_family = fhir_user['name'][0]['family']
                oauth_session.name_given = ''
                for user in fhir_user['name'][0]['given']:
                    if len(oauth_session.name_given) > 0:
                        oauth_session.name_given += ' '
                    oauth_session.name_given += user

    return blueprint
