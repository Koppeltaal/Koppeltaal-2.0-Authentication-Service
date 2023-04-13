import logging
from typing import Tuple
from urllib.parse import urlencode

import jwt as pyjwt
import requests
from flask import request, current_app

from application.oauth_server.model import Oauth2Session
from application.oauth_server.service import token_service

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
        state = request.values.get('state')
        if not state:
            logger.error('No state found on the authentication response')
            return 'Bad request, no state found on the authentication response', 400

        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(id=state).first()
        if not oauth2_session:
            logger.error(f'No session found based on id {state}')
            return 'Bad request, No session found based on id ' + state, 400

        hti_launch_token = pyjwt.decode(oauth2_session.launch, options={"verify_signature": False})
        logger.info(f'[{oauth2_session.id}] Consuming idp oidc code for user {hti_launch_token["sub"]}')

        code = request.values.get('code')
        if not code:
            logger.error(f'[{oauth2_session.id}] no code parameter found')
            return 'Bad request, no code found on the authentication response', 400

        # exchange the IDP code, we need the id_token from the response to verify the authenticated user matches the
        # user from the launch. This way we know the user really is the same person as the HTI token states.
        # When a launch token would be compromised, this logic would still make it useless as the identity needs to be
        # verified at the IDP
        oidc_token = self.exchange_idp_code(code)
        encoded_id_token = oidc_token['id_token']
        if not encoded_id_token:
            logger.error(f'[{oauth2_session.id}] no id_token found')
            return 'Bad request, no id_token found', 400

        id_token = pyjwt.decode(encoded_id_token, options={"verify_signature": False})  # TODO: Verify signature
        email = id_token['email']
        if not email:
            logger.error(f'[{oauth2_session.id}] no email found in id_token')
            return 'Bad request, no email found in id_token', 400

        logger.info(f'[{oauth2_session.id}] IdP id_token contains email [{email}]')

        # get the user from the FHIR server, to verify if the Patient has this email set as an identifier
        access_token = token_service.get_system_access_token()

        user_response = requests.get(f'{current_app.config["FHIR_CLIENT_SERVERURL"]}/{hti_launch_token["sub"]}', headers={"Authorization": "Bearer " + access_token})
        if not user_response.ok:
            logger.error(f'Failed to fetch user {hti_launch_token["sub"]} with error code [{user_response.status_code}] and message: \n{user_response.reason}')
            return 'Bad request, user could not be fetched from store', 400

        launching_user_resource = user_response.json()
        logger.debug(f'[{oauth2_session.id}] Found user resource from the fhir server with reference [{hti_launch_token["sub"]}]\n\nuser: {str(launching_user_resource)}')

        identifiers = launching_user_resource['identifier']
        values = [identifier['value'] for identifier in identifiers if 'value' in identifier]
        if email not in values:
            logger.error(f'[{oauth2_session.id}] user id mismatch, expected [{email}] but found {str(values)}')
            return 'Forbidden, patient email not found on Patient resource', 403

        logger.info(f'[{oauth2_session.id}] user id matched between HTI and IDP by email [{email}]')

        # As the user has been verified, finish the initial OAuth launch flow by responding with the code
        return f'{oauth2_session.redirect_uri}?{urlencode({"code": oauth2_session.code, "state": oauth2_session.state})}', 302

    @staticmethod
    def exchange_idp_code(code):
        payload = {
            'grant_type': 'authorization_code',
            'client_id': current_app.config['IDP_AUTHORIZE_CLIENT_ID'],
            'client_secret': current_app.config['IDP_AUTHORIZE_CLIENT_SECRET'],
            'code': code,
            'redirect_uri': current_app.config['IDP_AUTHORIZE_REDIRECT_URL']
        }

        return requests.post(current_app.config['IDP_TOKEN_ENDPOINT'],
                             data=payload,
                             headers={'content-type': "application/x-www-form-urlencoded"}
                             ).json()


idp_service = IdpService()
