import logging
from time import time
from typing import Dict, Any
from uuid import uuid4

import jwt as pyjwt
from authlib.jose import jwt
from flask import request, current_app
from jwt import PyJWKClient, InvalidSignatureError, DecodeError

from application.jwks.service import keypair_service
from application.oauth_server.model import Oauth2Token, SmartService, SmartServiceStatus

logger = logging.getLogger('oauth_service')
logger.setLevel(logging.DEBUG)

consumed_jti_tokens = []

class TokenService:
    def get_id_token(self, oauth2_token: Oauth2Token) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'],
                                   oauth2_token.client_id,
                                   sub=oauth2_token.subject,
                                   azp=oauth2_token.client_id)

    def get_access_token(self, oauth2_token: Oauth2Token, scope: str) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], 'fhir-server',
                                   type='access',
                                   sub=oauth2_token.subject,
                                   scope=scope,
                                   azp=oauth2_token.client_id)

    def get_system_access_token(self) -> str:
        return self._get_jwt_token(120, 'fhir-server',
                                   type='access',
                                   sub=current_app.config['SMART_BACKEND_SERVICE_CLIENT_ID'],
                                   azp=current_app.config['SMART_BACKEND_SERVICE_CLIENT_ID'])

    def get_refresh_token(self) -> str:
        return str(uuid4())

    def _get_jwt_token(self, expiry: int, aud: str, type: str = None, sub: str = None, email: str = None,
                       given_name: str = None, family_name: str = None, scope: str = None, azp: str = None) -> str:
        private_key, public_key = keypair_service.get_keypair()
        payload = {
            'iss': request.url_root,
            'aud': aud,
            'nbf': int(time()),
            'exp': int(time() + expiry),
            'nonce': str(uuid4())}
        if type is not None:
            payload['type'] = type

        if sub is not None:
            payload['sub'] = sub

        if email is not None:
            payload['email'] = email

        if given_name is not None:
            payload['given_name'] = given_name

        if family_name is not None:
            payload['family_name'] = family_name

        if scope is not None:
            payload['scope'] = scope

        if azp is not None:
            payload['azp'] = azp

        header = {'kid': public_key.thumbprint(), 'alg': 'RS512'}
        return jwt.encode(header, payload, private_key).decode('ascii')


class Oauth2ClientCredentialsService:
    """
    This class validates tokens issued by a registered application as smart_service.
    """
    consumed_jti_tokens = []

    def verify_and_get_token(self, encoded_token, expected_aud):

        logger.debug(f'Received encoded token: {encoded_token}')
        try:
            unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        except DecodeError as e:
            logger.warning(f"Failed to decode JWT: {e}")
            return

        if 'iss' not in unverified_decoded_jwt:
            logger.warning("JWT doesn't contain a iss value")
            return

        client_id = unverified_decoded_jwt['iss']

        logger.debug(
            f'Verifying received token with body: {unverified_decoded_jwt} and header: {pyjwt.get_unverified_header(encoded_token)}')

        smart_service: SmartService = self.get_smart_service(unverified_decoded_jwt)

        if not smart_service or smart_service.status != SmartServiceStatus.APPROVED:
            logger.warning(
                f"Discontinuing request for client_id {client_id}, smart service not found or status not approved")
            return

        if 'jti' not in unverified_decoded_jwt:
            logger.warning("JWT doesn't contain a jti value")
            return

        # FIXME: This should be checked against a shared cache like Redis to support multiple instances / ease of rebooting the  application
        if unverified_decoded_jwt['jti'] in consumed_jti_tokens:
            logger.warning(f"JWT is being replayed - jti {unverified_decoded_jwt['jti']} is already consumed")
            return

        consumed_jti_tokens.append(unverified_decoded_jwt['jti'])

        try:
            if smart_service.jwks_endpoint:
                return self.decode_with_jwks(smart_service, encoded_token, expected_aud)
            elif smart_service.public_key:
                return self.decode_with_public_key(smart_service, encoded_token, expected_aud)
            else:
                logger.error(f"No JWKS or Public Key found on smart service with client_id {client_id}", )
        except InvalidSignatureError as ise:
            logger.warning(f"Invalid signature for client_id {client_id}, exception {ise}")
            return
        except Exception as e:
            logger.warning(
                f"Something went wrong whilst trying to decode the JWT for client_id {client_id}, exception {e}")
            return

    def decode_with_jwks(self, smart_service, encoded_token, expected_aud) -> Dict[str, Any]:
        logger.info(f'Fetching endpoint: "{smart_service.jwks_endpoint}" for client_id: {smart_service.client_id}')
        jwks_client = PyJWKClient(smart_service.jwks_endpoint, cache_keys=False)
        signing_key = jwks_client.get_signing_key_from_jwt(encoded_token)
        decoded_jwt = pyjwt.decode(encoded_token, signing_key.key,
                                   algorithms=current_app.config['OIDC_SMART_CONFIG_SIGNING_ALGS'],
                                   audience=expected_aud)
        logger.info(f'JWT for client_id {smart_service.client_id} is decoded by JWKS - valid key')
        return decoded_jwt

    def decode_with_public_key(self, smart_service, encoded_token, expected_aud) -> Dict[str, Any]:

        public_key = smart_service.public_key

        if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
            logger.debug(
                f"public key for client_id {smart_service.client_id} didn't contain -----BEGIN PUBLIC KEY-----, injecting start and end tags")
            public_key = f'-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----'

        decoded_jwt = pyjwt.decode(encoded_token, public_key,
                                   algorithms=["RS512"],  ## TODO: check with spec
                                   audience=expected_aud)

        logger.info(f'JWT for client_id {smart_service.client_id} is decoded by PUBLIC KEY - valid key')
        return decoded_jwt

    def get_smart_service(self, unverified_decoded_jwt):
        issuer = unverified_decoded_jwt['iss']

        smart_service = SmartService.query.filter_by(client_id=issuer).first()
        logger.info(f'Matched issuer {issuer} to smart service {smart_service}')

        return smart_service


class ServerOauth2ClientCredentialsService():
    def verify_and_get_token(self, encoded_token):
        logger.debug(f'Received encoded token: {encoded_token}')
        unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        if 'iss' not in unverified_decoded_jwt:
            logger.warning("JWT doesn't contain a iss value")
            return
        iss = unverified_decoded_jwt['iss']
        if iss != request.url_root:
            logger.warning("JWT doesn't contain self as iss value")
            return

        if 'jti' not in unverified_decoded_jwt:
            logger.warning("JWT doesn't contain a jti value")
            return

        # FIXME: This should be checked against a shared cache like Redis to support multiple instances / ease of rebooting the  application
        if unverified_decoded_jwt['jti'] in consumed_jti_tokens:
            logger.warning(f"JWT is being replayed - jti {unverified_decoded_jwt['jti']} is already consumed")
            return

        consumed_jti_tokens.append(unverified_decoded_jwt['jti'])

        try:
            return self.decode_with_own_key(encoded_token)

        except InvalidSignatureError as ise:
            logger.warning(f"Invalid signature validating own key, exception {ise}")
            return
        except Exception as e:
            logger.warning(
                f"Something went wrong whilst trying to decode the JWT, exception {e}")
            return

    def decode_with_own_key(self, encoded_token):
        _, public_key = keypair_service.get_keypair()
        decoded_jwt = pyjwt.decode(encoded_token, public_key.as_pem(),
                                   algorithms=current_app.config[
                                       'OIDC_SMART_CONFIG_SIGNING_ALGS'],
                                   audience=current_app.config[
                                       'OIDC_SMART_CONFIG_TOKEN_ENDPOINT'])

        logger.info(f'JWT signed by self is decoded by JWKS - valid key')
        return decoded_jwt


class SmartHtiOnFhirService:
    def __init__(self):
        pass

    def validate_launch_token(self, encoded_token: str):
        unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        issuer = unverified_decoded_jwt['iss']

        if not unverified_decoded_jwt['jti']:
            logger.warning("JWT doesn't contain a jti value")
            return

        # FIXME: This should be checked against a shared cache like Redis to support multiple instances / ease of rebooting the  application
        if unverified_decoded_jwt['jti'] in consumed_jti_tokens:
            logger.warning(f"JWT is being replayed - jti {unverified_decoded_jwt['jti']} is already consumed")
            return

        consumed_jti_tokens.append(unverified_decoded_jwt['jti'])

        smart_service: SmartService = self.get_smart_service(issuer)
        if not smart_service:
            logger.warning(f"Cannot find smart_service for issuer: {issuer}")
            return

        try:
            if smart_service.jwks_endpoint:
                return self.decode_with_jwks(smart_service, encoded_token)
            elif smart_service.public_key:
                return self.decode_with_public_key(smart_service, encoded_token)
            else:
                logger.error(f"No JWKS or Public Key found on smart service with client_id {issuer}")
        except InvalidSignatureError as ise:
            logger.warning(f"Invalid signature for client_id {issuer}, exception {ise}")
            return
        except Exception as e:
            logger.warning(
                f"Something went wrong whilst trying to decode the JWT for client_id {issuer}, exception {e}")
            return

    def decode_with_jwks(self, smart_service, encoded_token):
        logger.info(f'Fetching endpoint: "{smart_service.jwks_endpoint}" for client_id: {smart_service.client_id}')
        jwks_client = PyJWKClient(smart_service.jwks_endpoint, cache_keys=False)  ## Caching does not respect the TTL,just has a number of keys
        signing_key = jwks_client.get_signing_key_from_jwt(encoded_token)
        decoded_jwt = pyjwt.decode(encoded_token, signing_key.key,
                                   algorithms=current_app.config[
                                       'OIDC_SMART_CONFIG_SIGNING_ALGS'],
                                   options={'verify_aud': False})

        logger.info(f'JWT for client_id {smart_service.client_id} is decoded by JWKS - valid key')
        return decoded_jwt

    def decode_with_public_key(self, smart_service, encoded_token):

        public_key = smart_service.public_key

        if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
            logger.debug(
                f"public key for client_id {smart_service.client_id} didn't contain -----BEGIN PUBLIC KEY-----, injecting start and end tags")
            public_key = '-----BEGIN PUBLIC KEY-----\n' + public_key + '\n-----END PUBLIC KEY-----'
        decoded_jwt = pyjwt.decode(encoded_token, public_key,
                                   algorithms=["RS512"],
                                   options={'verify_aud': False})

        logger.info(f'JWT for client_id {smart_service.client_id} is decoded by PUBLIC KEY - valid key')
        return decoded_jwt

    def get_smart_service(self, client_id):
        smart_service = SmartService.query.filter_by(client_id=client_id).first()
        logger.info(f'Matched issuer {client_id} to smart service {smart_service}')

        return smart_service


smart_hti_on_fhir_service = SmartHtiOnFhirService()
token_service = TokenService()
oauth2_client_credentials_service = Oauth2ClientCredentialsService()
server_oauth2_service = ServerOauth2ClientCredentialsService()


"""
headease-koppeltaal-koppeltaal-2-0-smart-service-testsuite-staging.koppeltaal.headease.nl
"""
