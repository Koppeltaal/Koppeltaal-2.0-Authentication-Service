#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

import json
from encodings.base64_codec import base64_decode
from json import JSONDecodeError
from urllib.parse import urlencode
from uuid import uuid4

from authlib.jose import jwt
from flask import Blueprint, redirect, request, jsonify, current_app, render_template, session

from application.database import db
from application.fhir_client import fhir_client
from application.irma_client import irma_client
from application.oidc_server.model import Oauth2Session, Oauth2Token
from application.oidc_server.service import token_service


def create_blueprint() -> Blueprint:
    blueprint = Blueprint(__name__.split('.')[-2], __name__)

    @blueprint.route('/oauth2/authorize')
    def authorize():
        oauth_session = Oauth2Session()

        oauth_session.scope = request.values.get('scope')
        oauth_session.response_type = request.values.get('response_type')
        oauth_session.client_id = request.values.get('client_id')
        oauth_session.redirect_uri = request.values.get('redirect_uri')
        oauth_session.state = request.values.get('state')
        oauth_session.launch = request.values.get('launch', None)
        oauth_session.code = str(uuid4())

        if 'username' in session:  # Fixme:
            username = session['username']
            _update_fhir_user(oauth_session, username)

        db.session.add(oauth_session)
        db.session.commit()

        return route_from_authorise(oauth_session)

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
        else:
            return 'Bad Request', 400

    @blueprint.route('/oauth2/irma-auth')
    def irma_auth():
        token = request.values['token']
        oauth_session_id = request.values['session']

        username = irma_client.validate_token(token)

        oauth_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth_session_id).first()
        # if oauth_session.launch:
        #     jwt.decode(oauth_session.launch, )
        _update_fhir_user(oauth_session, username)

        db.session.commit()

        if not oauth_session.consent:
            return redirect('/oauth2/consent?' + urlencode({'session': oauth_session.id}))
        else:
            return redirect(
                f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')

    def route_from_authorise(oauth_session):
        # If the username is set, the user is identified.
        if not oauth_session.username is None:
            if not oauth_session.consent:
                return redirect('/oauth2/consent?' + urlencode({'session': oauth_session.id}))
            else:
                return redirect(
                    f'{oauth_session.redirect_uri}?{urlencode({"code": oauth_session.code, "state": oauth_session.state})}')
        return redirect(irma_client.get_redirect_url({'session': oauth_session.id}))

    def token_refresh_token():
        refresh_token = request.values.get('refresh_token')

        scope = request.values.get('scope')
        oauth2_token: Oauth2Token = Oauth2Token.query.filter_by(refresh_token=refresh_token).first()
        if oauth2_token is None:
            print(f'Cannot locate Oauth2Token with refresh token {refresh_token}')
            return 'Bad Request', 400

        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(id=oauth2_token.session_id).first()
        if oauth2_session is None:
            return 'Bad Request', 400

        assert scope == oauth2_token.scope
        oauth2_token.id_token = token_service.get_id_token(oauth2_token)
        oauth2_token.access_token = token_service.get_access_token(oauth2_token, oauth2_session)
        if oauth2_token.refresh_token is None:
            oauth2_token.refresh_token = token_service.get_refresh_token()
        db.session.add(oauth2_token)
        json = oauth2_token_to_json(oauth2_token, oauth2_session)
        db.session.commit()
        return jsonify(json)

    def oauth2_token_to_json(oauth2_token: Oauth2Token, oauth2_session: Oauth2Session):
        rv = {'access_token': oauth2_token.access_token,
              "token_type": "Bearer",
              "refresh_token": oauth2_token.refresh_token,
              "id_token": oauth2_token.id_token,
              "expires_in": current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN']}

        if oauth2_session.launch and oauth2_session.launch.count('.') == 2:
            try:
                body_encoded = oauth2_session.launch.split('.')[1]
                body = json.loads(base64_decode(body_encoded.encode('ascii') + b'===')[0].decode('ascii'))
                if 'task' in body:
                    task = body['task']
                    if 'owner' in task:
                        rv['patient'] = task['owner']['reference']
                    if 'definitionReference' in task:
                        rv['task'] = task['definitionReference']['reference']
                    if 'requester' in task:
                        rv['practitioner'] = body['requester']['reference']
            except JSONDecodeError:
                print(f'Failed to process token: {oauth2_session.launch}')

        return rv

    def token_authorization_code():
        code = request.values.get('code')
        redirect_uri = request.values.get('redirect_uri')
        ## TODO: The token request must be autheticated.
        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(code=code).first()
        assert redirect_uri == oauth2_session.redirect_uri
        oauth2_token = Oauth2Token()
        oauth2_token.email = oauth2_session.email
        oauth2_token.name_family = oauth2_session.name_family
        oauth2_token.name_given = oauth2_session.name_given
        oauth2_token.subject = oauth2_session.user_fhir_reference
        oauth2_token.scope = oauth2_session.scope
        oauth2_token.client_id = oauth2_session.client_id
        oauth2_token.id_token = token_service.get_id_token(oauth2_token)
        oauth2_token.access_token = token_service.get_access_token(oauth2_token, oauth2_session)
        oauth2_token.refresh_token = token_service.get_refresh_token()
        oauth2_token.session_id = oauth2_session.id
        db.session.add(oauth2_token)
        db.session.commit()
        return jsonify(oauth2_token_to_json(oauth2_token, oauth2_session))

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
