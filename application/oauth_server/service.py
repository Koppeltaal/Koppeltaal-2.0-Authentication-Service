import logging
from time import time
from uuid import uuid4

import jwt as pyjwt
from authlib.jose import Key, JsonWebKey
from authlib.jose import jwt
from flask import request, current_app
from jwt import PyJWKClient, InvalidSignatureError

from application.oauth_server.model import Oauth2Token, SmartService, SmartServiceStatus

logger = logging.getLogger('oauth_service')
logger.setLevel(logging.DEBUG)


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

    def get_system_access_token(self, username: str) -> str:
        return self._get_jwt_token(120, 'fhir-server', 'access', username, None,
                                   'user/Patient.read user/Practitioner.read user/RelatedPerson.read user/Person.read')

    def get_refresh_token(self) -> str:
        return str(uuid4())

    def _get_jwt_token(self, expiry: int, aud: str, type: str = None, sub: str = None, email: str = None,
                       given_name: str = None, family_name: str = None, scope: str = None, azp: str = None) -> str:
        private_key, public_key = self.get_keypair()
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

    def get_keypair(self):
        public_key: Key = JsonWebKey.import_key(current_app.config['OIDC_JWT_PUBLIC_KEY'])
        private_key: Key = JsonWebKey.import_key(current_app.config['OIDC_JWT_PRIVATE_KEY'])
        return private_key, public_key


class Oauth2ClientCredentialsService:
    consumed_jti_tokens = []

    def verify_and_get_token(self):
        encoded_token = request.form.get('client_assertion')

        logger.debug(f'Received encoded token: {encoded_token}')
        unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        client_id = unverified_decoded_jwt['iss']

        logger.debug(f'Verifying received token with body: {unverified_decoded_jwt} and header: {pyjwt.get_unverified_header(encoded_token)}')

        smart_service: SmartService = self.get_smart_service(unverified_decoded_jwt)

        if not smart_service or smart_service.status != SmartServiceStatus.APPROVED:
            logger.warning(
                f"Discontinuing request for client_id {client_id}, smart service not found or status not approved")
            return

        if not unverified_decoded_jwt['jti']:
            logger.warning("JWT doesn't contain a jti value")
            return

        # FIXME: This should be checked against a shared cache like Redis to support multiple instances / ease of rebooting the  application
        if unverified_decoded_jwt['jti'] in self.consumed_jti_tokens:
            logger.warning(f"JWT is being replayed - jti {unverified_decoded_jwt['jti']} is already consumed")
            return

        self.consumed_jti_tokens.append(unverified_decoded_jwt['jti'])

        try:
            if smart_service.jwks_endpoint:
                return self.decode_with_jwks(smart_service, encoded_token)
            elif smart_service.public_key:
                return self.decode_with_public_key(smart_service, encoded_token)
            else:
                logger.error(f"No JWKS or Public Key found on smart service with client_id {client_id}", )
        except InvalidSignatureError as ise:
            logger.warning(f"Invalid signature for client_id {client_id}, exception {ise}")
            return
        except Exception as e:
            logger.warning(
                f"Something went wrong whilst trying to decode the JWT for client_id {client_id}, exception {e}")
            return

    def decode_with_jwks(self, smart_service, encoded_token):

        jwks_client = PyJWKClient(smart_service.jwks_endpoint)
        signing_key = jwks_client.get_signing_key_from_jwt(encoded_token)
        decoded_jwt = pyjwt.decode(encoded_token, signing_key.key,
                                   algorithms=current_app.config[
                                       'OIDC_SMART_CONFIG_SIGNING_ALGS'],
                                   audience=current_app.config[
                                       'OIDC_SMART_CONFIG_TOKEN_ENDPOINT'])

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
                                   audience=current_app.config[
                                       'OIDC_SMART_CONFIG_TOKEN_ENDPOINT'])

        logger.info(f'JWT for client_id {smart_service.client_id} is decoded by PUBLIC KEY - valid key')
        return decoded_jwt

    def get_smart_service(self, unverified_decoded_jwt):
        issuer = unverified_decoded_jwt['iss']
        subject = unverified_decoded_jwt['sub']
        client_assertion_type = request.form.get('client_assertion_type')

        if issuer != subject or client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
            logger.warning(
                f'Invalid JWT - issuer != subject == {issuer != subject} and client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" == {client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}')

            return

        smart_service = SmartService.query.filter_by(client_id=issuer).first()
        logger.info(f'Matched issuer {issuer} to smart service {smart_service}')

        return smart_service


class SmartHtiOnFhirService:
    def __init__(self):
        self.consumed_jti_tokens = []

    def validate_launch_token(self, encoded_token: str, audience: str):
        unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        issuer = unverified_decoded_jwt['iss']
        ## The audience is expected to be the client id of the recieving application.
        assert audience == unverified_decoded_jwt['aud']

        if not unverified_decoded_jwt['jti']:
            logger.warning("JWT doesn't contain a jti value")
            return

        # FIXME: This should be checked against a shared cache like Redis to support multiple instances / ease of rebooting the  application
        if unverified_decoded_jwt['jti'] in self.consumed_jti_tokens:
            logger.warning(f"JWT is being replayed - jti {unverified_decoded_jwt['jti']} is already consumed")
            return

        self.consumed_jti_tokens.append(unverified_decoded_jwt['jti'])

        smart_service: SmartService = self.get_smart_service(issuer)

        try:
            if smart_service.jwks_endpoint:
                return self.decode_with_jwks(smart_service, encoded_token, audience)
            elif smart_service.public_key:
                return self.decode_with_public_key(smart_service, encoded_token, audience)
            else:
                logger.error(f"No JWKS or Public Key found on smart service with client_id {issuer}")
        except InvalidSignatureError as ise:
            logger.warning(f"Invalid signature for client_id {issuer}, exception {ise}")
            return
        except Exception as e:
            logger.warning(
                f"Something went wrong whilst trying to decode the JWT for client_id {issuer}, exception {e}")
            return

    def decode_with_jwks(self, smart_service, encoded_token, audience):

        jwks_client = PyJWKClient(smart_service.jwks_endpoint)
        signing_key = jwks_client.get_signing_key_from_jwt(encoded_token)
        decoded_jwt = pyjwt.decode(encoded_token, signing_key.key,
                                   algorithms=current_app.config[
                                       'OIDC_SMART_CONFIG_SIGNING_ALGS'],
                                   options={'verify_aud': False})

        logger.info(f'JWT for client_id {smart_service.client_id} is decoded by JWKS - valid key')
        return decoded_jwt

    def decode_with_public_key(self, smart_service, encoded_token, audience):

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
