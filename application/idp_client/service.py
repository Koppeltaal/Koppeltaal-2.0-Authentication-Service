import logging
from typing import Tuple
from urllib.parse import urlencode
from uuid import uuid4

import jwt as pyjwt
import requests
from flask import request, current_app

from application.fhir_logging_client.service import fhir_logging_service
from application.oauth_server.model import Oauth2Session, IdentityProvider
from application.oauth_server.service import token_service
from application.utils import new_trace_headers

logger = logging.getLogger('idp_service')
logger.setLevel(logging.DEBUG)

'''
The IdP service is used for communication with the configured IdP. During the /authorize call in the `oauth_server` 
module, this service will be called to verify that the subject of the JWT (during a launch) actually matches the 
currently logged in user. The service executed an OIDC auth code flow to retrieve the `id_token` and ensures
the launch is performed by the actual user 
'''
class IdpService:
    def consume_idp_code(self) -> Tuple[str, int]:
        user_claim = "email"

        state = request.values.get('state')
        trace_headers = self._get_trace_headers()

        if not state:
            logger.error('No state found on the authentication response')
            return 'Bad request, no state found on the authentication response', 400

        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(id=state).first()
        if not oauth2_session:
            logger.error(f'No session found based on id {state}')
            return 'Bad request, No session found based on id ' + state, 400

        hti_launch_token = pyjwt.decode(oauth2_session.launch, options={"verify_signature": False})
        logger.info(f'[{oauth2_session.id}] Consuming idp oidc code for user {hti_launch_token["sub"]}')

        if 'X-Trace-Id' not in trace_headers:
            trace_headers['X-Trace-Id'] = hti_launch_token['jti']  # The JTI token is the trace id if not set

        code = request.values.get('code')
        if not code:
            logger.error(f'[{oauth2_session.id}] no code parameter found')
            return 'Bad request, no code found on the authentication response', 400

        # exchange the IDP code, we need the id_token from the response to verify the authenticated user matches the
        # user from the launch. This way we know the user really is the same person as the HTI token states.
        # When a launch token would be compromised, this logic would still make it useless as the identity needs to be
        # verified at the IDP
        oidc_token = self.exchange_idp_code(code, oauth2_session)
        logger.info(f"Received oidc token: {oidc_token}")
        encoded_id_token = oidc_token['id_token']
        if not encoded_id_token:
            logger.error(f'[{oauth2_session.id}] no id_token found')
            return 'Bad request, no id_token found', 400

        id_token = pyjwt.decode(encoded_id_token, options={"verify_signature": False})  # TODO: Verify signature

        if oauth2_session.identity_provider:
            identity_provider: IdentityProvider = IdentityProvider.query.filter_by(id=oauth2_session.identity_provider).first()
            user_claim = identity_provider.username_attribute  # overwrite the default claim "email"

        user_identifier = id_token[user_claim]
        if not user_identifier:
            logger.error(f'[{oauth2_session.id}] no [{user_claim}] claim found in id_token')
            return f'Bad request, no [{user_claim}] claim found in id_token', 400

        logger.info(f'[{oauth2_session.id}] IdP id_token contains claim [{user_claim}] with value [{user_identifier}]')

        # get the user from the FHIR server, to verify if the Patient has this email set as an identifier
        access_token = token_service.get_system_access_token()

        headers = new_trace_headers(trace_headers, {"Authorization": "Bearer " + access_token})

        user_response = requests.get(f'{current_app.config["FHIR_CLIENT_SERVERURL"]}/{hti_launch_token["sub"]}', headers=headers)
        if not user_response.ok:
            logger.error(f'Failed to fetch user {hti_launch_token["sub"]} with error code [{user_response.status_code}] and message: \n{user_response.reason}')
            return 'Bad request, user could not be fetched from store', 400

        launching_user_resource = user_response.json()
        logger.debug(f'[{oauth2_session.id}] Found user resource from the fhir server with reference [{hti_launch_token["sub"]}]\n\nuser: {str(launching_user_resource)}')

        identifiers = launching_user_resource['identifier']
        values = [identifier['value'] for identifier in identifiers if 'value' in identifier]
        if user_identifier not in values:
            logger.error(f'[{oauth2_session.id}] user id mismatch, expected [{user_identifier}] but found {str(values)}')
            return f'Forbidden, patient identifier [{user_identifier}] not found on [Patient/{launching_user_resource["id"]}]', 403

        logger.info(f'[{oauth2_session.id}] user id matched between HTI and IDP by user_identifier [{user_identifier}]')

        fhir_logging_service.register_idp_interaction(f'Patient/{launching_user_resource["id"]}', trace_headers)

        # As the user has been verified, finish the initial OAuth launch flow by responding with the code
        return f'{oauth2_session.redirect_uri}?{urlencode({"code": oauth2_session.code, "state": oauth2_session.state})}', 302

    def _get_trace_headers(self):
        trace_headers = {
            'X-Request-Id': request.headers.get('X-Request-Id', str(uuid4()))
        }
        if 'X-Correlation-Id' in request.headers:
            trace_headers['X-Correlation-Id'] = request.headers['X-Correlation-Id']
        if 'X-Trace-Id' in request.headers:
            trace_headers['X-Trace-Id'] = request.headers['X-Trace-Id']

        return trace_headers

    @staticmethod
    def exchange_idp_code(code, oauth2_session: Oauth2Session):

        identity_provider = IdentityProvider.query.filter_by(id=oauth2_session.identity_provider).first() \
            if oauth2_session.identity_provider else None

        payload = {
            'grant_type': 'authorization_code',
            'client_id': identity_provider.client_id if identity_provider else current_app.config['IDP_AUTHORIZE_CLIENT_ID'],
            'client_secret': identity_provider.client_secret if identity_provider else current_app.config['IDP_AUTHORIZE_CLIENT_SECRET'],
            'code': code,
            'redirect_uri': current_app.config['IDP_AUTHORIZE_REDIRECT_URL']
        }

        if identity_provider:
            data = requests.get(identity_provider.openid_config_endpoint).json()
            return requests.post(data['token_endpoint'],
                                 data=payload,
                                 headers={'content-type': "application/x-www-form-urlencoded"}
                                 ).json()

        return requests.post(current_app.config['IDP_TOKEN_ENDPOINT'],
                             data=payload,
                             headers={'content-type': "application/x-www-form-urlencoded"}
                             ).json()


idp_service = IdpService()
