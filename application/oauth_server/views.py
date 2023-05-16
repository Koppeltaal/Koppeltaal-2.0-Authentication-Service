#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
import json
import logging
import urllib.request
from json import JSONDecodeError
from urllib.parse import urlencode
from uuid import uuid4

import jwt as pyjwt
from encodings.base64_codec import base64_decode
from flask import Blueprint, redirect, request, jsonify, current_app

from application.database import db
from application.oauth_server.model import Oauth2Session, Oauth2Token, SmartService, IdentityProvider
from application.oauth_server.scopes import scope_service
from application.oauth_server.service import token_service, oauth2_client_credentials_service, \
    smart_hti_on_fhir_service, server_oauth2_service, token_authorization_code_service, LAUNCH_SCOPE_DEFAULT

logger = logging.getLogger('oauth_views')
logger.setLevel(logging.DEBUG)


def create_blueprint() -> Blueprint:
    blueprint = Blueprint(__name__.split('.')[-2], __name__)

    @blueprint.errorhandler(AssertionError)
    def handle_assertionerror(e):
        print(f'Catching assertion error {e}, returning 400')
        # TODO: In a live production environment, the exception should not be provided - helps in this PoC
        return f'Bad Request, assertion failed: {e}', 400

    @blueprint.route('/oauth2/authorize')
    def handle_authorize_request():
        oauth2_session = Oauth2Session()
        oauth2_session.type = 'smart_hti_on_fhir'
        scope = request.values.get('scope', LAUNCH_SCOPE_DEFAULT)
        oauth2_session.scope = scope
        oauth2_session.code_challenge = request.values.get('code_challenge')
        oauth2_session.code_challenge_method = request.values.get('code_challenge_method')
        oauth2_session.response_type = request.values.get('response_type')
        oauth2_session.client_id = request.values.get('client_id')
        oauth2_session.redirect_uri = request.values.get('redirect_uri')
        oauth2_session.state = request.values.get('state')
        oauth2_session.launch = request.values.get('launch', None)
        oauth2_session.aud = request.values.get('aud', None)
        oauth2_session.code = str(uuid4())

        db.session.add(oauth2_session)
        db.session.commit()

        assert current_app.config['FHIR_CLIENT_SERVERURL'] == oauth2_session.aud, "Invalid audience"
        launch_token = smart_hti_on_fhir_service.validate_launch_token(oauth2_session.launch)
        if launch_token:
            # If the JWT is valid, we have to verify that the launch token was not compromised by executing another
            # OIDC flow against the shared IDP. The user should already be logged in here, or a login will be
            # prompted. The username has to be present as a Patient.identifier
            scopes = smart_hti_on_fhir_service.validate_and_parse_launch_scope(scope, launch_token)
            if not scopes:
                return 'Bad Request, invalid scope', 400
            if 'openid' in scopes:
                parameters = {"response_type": "code",
                              "client_id": current_app.config["IDP_AUTHORIZE_CLIENT_ID"],
                              "state": oauth2_session.id,
                              "redirect_uri": current_app.config["IDP_AUTHORIZE_REDIRECT_URL"],
                              "scope": "openid",
                              "login": "true"}

                # Check if the smart service has a custom IDP
                smart_service: SmartService = smart_hti_on_fhir_service.get_smart_service(oauth2_session.client_id)
                launch_sub: str = launch_token['sub']

                if launch_sub and launch_sub.startswith('Practitioner') and smart_service and smart_service.practitioner_idp:
                    identity_provider: IdentityProvider = IdentityProvider.query.filter_by(id=smart_service.practitioner_idp).first()
                    oauth2_session.identity_provider = identity_provider.id
                    db.session.commit()

                    with urllib.request.urlopen(identity_provider.endpoint) as url:
                        data = json.load(url)
                        return redirect(f'{data["authorization_endpoint"]}?{urlencode(parameters)}')

                if launch_sub and launch_sub.startswith('Patient') and smart_service and smart_service.patient_idp:
                    identity_provider: IdentityProvider = IdentityProvider.query.filter_by(id=smart_service.patient_idp).first()
                    oauth2_session.identity_provider = identity_provider.id
                    db.session.commit()

                    with urllib.request.urlopen(identity_provider.endpoint) as url:
                        data = json.load(url)
                        return redirect(f'{data["authorization_endpoint"]}?{urlencode(parameters)}')

                # Otherwise send to the default IDP
                return redirect(f'{current_app.config["IDP_AUTHORIZE_ENDPOINT"]}?{urlencode(parameters)}')
            else:
                return redirect(
                    f'{oauth2_session.redirect_uri}?{urlencode({"code": oauth2_session.code, "state": oauth2_session.state})}')
        return 'Bad Request, invalid launch token', 400

    @blueprint.route('/oauth2/token', methods=['POST', 'GET'])
    def handle_token_request():
        jwt = _do_client_assertion()
        if jwt:
            grant_type = request.values.get('grant_type')
            if grant_type == 'authorization_code':
                return _token_authorization_code(jwt)
            if grant_type == 'client_credentials':
                return _token_client_credentials(jwt)
            else:
                return 'Bad Request', 400

        logger.info("Invalid client credential request - returning access denied")
        return 'Access Denied', 401

    @blueprint.route('/oauth2/introspect', methods=['POST'])
    def handle_introspect_request():
        """
        There are 3 types of JWT tokens:
         - launch token (client id from launching party, aud launch URL),
         - client_credential(assertion-type urn:ietf:params:oauth:client-assertion-type:jwt-bearer) token
         - access_token (iss = myself)
        :return:
        """
        jwt = _do_client_assertion()
        if jwt:
            token = request.values.get('token')
            if not token:
                return 'Bad Request, required field token missing', 400

            unverified_decoded_jwt = pyjwt.decode(token, options={"verify_signature": False})
            iss = unverified_decoded_jwt.get('iss')
            if not iss:
                return jsonify({'active': False})

            if iss == request.url_root:  # signed by self
                decoded = server_oauth2_service.verify_and_get_token(token)
            else:
                decoded = oauth2_client_credentials_service.verify_and_get_token(token)

            if decoded:
                # TODO: validate fields
                rv = decoded.copy()
                rv['active'] = True
                return jsonify(rv)
            return jsonify({'active': False})
        logger.info("Invalid introspect request - returning access denied")
        return 'Access Denied', 401

    def _do_client_assertion():
        client_assertion_type = request.values.get('client_assertion_type')
        # Check if the client_assertion_type is set correctly.
        if client_assertion_type == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer':
            encoded_token = request.values.get('client_assertion')
            return oauth2_client_credentials_service.verify_and_get_token(encoded_token)
        else:
            logger.info(f"Invalid client_assertion_type received: {client_assertion_type}")

    def _oauth2_token_task_to_json(oauth2_token: Oauth2Token, oauth2_session: Oauth2Session = None):
        rv = {'access_token': oauth2_token.access_token,
              "token_type": "Bearer",
              "expires_in": current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN']}

        if oauth2_token.id_token:
            rv['id_token'] = oauth2_token.id_token

        if oauth2_token.scope:
            rv['scope'] = oauth2_token.scope

        if oauth2_token.refresh_token:
            rv['refresh_token'] = oauth2_token.refresh_token

        if oauth2_token.subject:
            subject: str = oauth2_token.subject
            rv['sub'] = subject  ## Should be the same as the Task.for (1.1) or sub (1.2) fields.

        hti_body = _get_launch_token_body(oauth2_session)
        if 'task' in hti_body:  ## Check for HTI 1.1
            task = hti_body['task']
            if 'id' in task:
                rv['resource'] = f'Task/{task["id"]}'
            if 'instantiatesCanonical' in task:
                rv['definition'] = task['instantiatesCanonical']  ## TODO: chop whole URL?
            copy_value_if_exists('intend', task, rv)

        else:  ## Assume HTI 2.0
            copy_value_if_exists('resource', hti_body, rv)  # AKA Task
            copy_value_if_exists('definition', hti_body, rv)  # AKA TaskDefinition
            copy_value_if_exists('patient', hti_body, rv)  # In case of a launch on behalf: the patient
            copy_value_if_exists('intent', hti_body, rv)

            copy_value_if_exists('aud', hti_body, rv)
            copy_value_if_exists('iss', hti_body, rv)
            copy_value_if_exists('exp', hti_body, rv)
            copy_value_if_exists('jti', hti_body, rv)

        return rv

    def copy_value_if_exists(field, source, target):
        if field in source:
            target[field] = source[field]

    def _token_authorization_code(jwt):
        code = request.values.get('code')
        redirect_uri = request.values.get('redirect_uri')
        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(code=code).first()
        assert redirect_uri == oauth2_session.redirect_uri, f'Expected redirect_uri [{oauth2_session.redirect_uri}], got [{redirect_uri}] instead'
        assert oauth2_session.client_id == jwt['iss'], f'Expected issuer [{oauth2_session.client_id}], got [{jwt["iss"]}] instead'
        assert oauth2_session.type == 'smart_hti_on_fhir', f'Expected session type to be [smart_hti_on_fhir], its actually [{oauth2_session.type}]'

        if not token_authorization_code_service.check_challenge(oauth2_session.code_challenge,
                                                                request.values.get('code_verifier'),
                                                                oauth2_session.code_challenge_method):
            logger.info("Invalid challenge and verifier - returning access denied")
            return 'Access Denied', 401

        return _oauth_token_smart_hti_on_fhir(oauth2_session)

    def _oauth_token_smart_hti_on_fhir(oauth2_session: Oauth2Session):
        oauth2_token = Oauth2Token()
        oauth2_token.subject = oauth2_session.user_fhir_reference
        oauth2_token.client_id = oauth2_session.client_id
        body = _get_launch_token_body(oauth2_session)

        oauth2_token.subject = body['sub']

        oauth2_token.scope = oauth2_session.scope
        oauth2_token.client_id = oauth2_session.client_id
        oauth2_token.id_token = token_service.get_id_token(oauth2_token)
        ## NOOP:
        oauth2_token.access_token = 'NOOP'
        ## None:
        oauth2_token.refresh_token = ''
        oauth2_token.session_id = oauth2_session.id
        db.session.add(oauth2_token)
        db.session.commit()
        return jsonify(_oauth2_token_task_to_json(oauth2_token, oauth2_session))

    def _get_launch_token_body(oauth2_session):
        body = {}
        if oauth2_session and oauth2_session.launch and oauth2_session.launch.count('.') == 2:
            try:
                body_encoded = oauth2_session.launch.split('.')[1]
                body = json.loads(base64_decode(body_encoded.encode('ascii') + b'===')[0].decode('ascii'))
            except JSONDecodeError:
                print(f'Failed to process token: {oauth2_session.launch}')
        return body

    # private_key_jwt flow https://hl7.org/fhir/uv/bulkdata/authorization/index.html#obtaining-an-access-token
    def _token_client_credentials(jwt):
        issuer = jwt['iss']
        smart_service: SmartService = SmartService.query.filter_by(client_id=issuer).first()
        assert smart_service is not None, f'Could not find SMART service with client_id [{issuer}]'
        scope = scope_service.get_scope_str(smart_service.role_id, smart_service.fhir_store_device_id) if smart_service.role_id else ''
        logger.info(f"Generating OAuth access token for issuer {issuer} with scope {scope}")
        oauth2_token = Oauth2Token()
        oauth2_token.client_id = issuer
        oauth2_token.scope = scope
        oauth2_token.access_token = token_service.get_access_token(oauth2_token, scope)
        # In the client_credentials flow, the refresh_token is not allowed
        # oauth2_token.refresh_token = token_service.get_refresh_token()
        db.session.add(oauth2_token)
        db.session.commit()
        return jsonify(_oauth2_token_task_to_json(oauth2_token))

    return blueprint
