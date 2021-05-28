from time import time
from uuid import uuid4

from authlib.jose import Key, JsonWebKey
from authlib.jose import jwt
from flask import request, current_app

import jwt as pyjwt
from jwt import PyJWKClient

import logging

from application.database import db
from application.oauth_server.model import Oauth2Token, Oauth2ClientCredentials, \
    SmartService, SmartServiceStatus

logger = logging.getLogger('oauth_service')
logger.setLevel(logging.DEBUG)


class TokenService:
    def get_id_token(self, oauth2_token: Oauth2Token) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], oauth2_token.client_id,
                                   sub=oauth2_token.subject, email=oauth2_token.email,
                                   given_name=oauth2_token.name_given, family_name=oauth2_token.name_family)

    def get_access_token(self, oauth2_token: Oauth2Token, scope: str) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], 'fhir-server', type='access',
                                   sub=oauth2_token.subject, scope=scope)

    def get_system_access_token(self, username: str) -> str:
        return self._get_jwt_token(120, 'fhir-server', 'access', username, None,
                                   'user/Patient.read user/Practitioner.read user/RelatedPerson.read user/Person.read')

    def get_refresh_token(self) -> str:
        return str(uuid4())

    def _get_jwt_token(self, expiry: int, aud: str, type: str = None, sub: str = None, email: str = None,
                       given_name: str = None, family_name: str = None, scope: str = None) -> str:
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

        unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        client_id = unverified_decoded_jwt['iss']

        logger.debug('Verifying received token: [%s]', unverified_decoded_jwt)

        smart_service: SmartService = self.get_smart_service(unverified_decoded_jwt)

        if not smart_service or smart_service.status != SmartServiceStatus.APPROVED:
            logger.warning("Discontinuing request for client_id [%s], smart service not found or status not approved", client_id)
            return

        if not unverified_decoded_jwt['jti']:
            logger.warning("JWT doesn't contain a jti value")
            return

        #FIXME: This should be checked against a shared cache like Redis to support multiple instances / ease of rebooting the  application
        if unverified_decoded_jwt['jti'] in self.consumed_jti_tokens:
            logger.warning("JWT is being replayed - jti [%s] is already consumed", unverified_decoded_jwt['jti'])
            return

        self.consumed_jti_tokens.append(unverified_decoded_jwt['jti'])

        jwks_client = PyJWKClient(smart_service.jwks_endpoint)
        signing_key = jwks_client.get_signing_key_from_jwt(encoded_token)

        decoded_jwt = pyjwt.decode(encoded_token, signing_key.key,
                                   algorithms=current_app.config['OIDC_SMART_CONFIG_SIGNING_ALGS'],
                                   audience=current_app.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT'])
        logger.info('JWT for client_id [%s] is decoded - valid key', client_id)

        return decoded_jwt

    def get_smart_service(self, unverified_decoded_jwt):
        issuer = unverified_decoded_jwt['iss']
        subject = unverified_decoded_jwt['sub']
        client_assertion_type = request.form.get('client_assertion_type')

        if issuer != subject or client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
            logger.warning(
                'Invalid JWT - issuer != subject == [%s] and client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" == [%s]',
                issuer != subject,
                client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )

            return

        smart_service = SmartService.query.filter_by(client_id=issuer).first()
        logger.info('Matched issuer [%s] to smart service [%s]', issuer, smart_service)

        return smart_service

    def check_client_credentials(self, client_id: str, client_secret: str):
        credentials: Oauth2ClientCredentials = Oauth2ClientCredentials.query.filter_by(client_id=client_id).first()
        if credentials:
            return client_secret == credentials.client_secret
        return False

    def store_client_credentials(self, client_id: str, client_secret: str):
        credentials: Oauth2ClientCredentials = Oauth2ClientCredentials.query.filter_by(client_id=client_id).first()
        if not credentials:
            credentials = Oauth2ClientCredentials()
            credentials.client_id = client_id

        credentials.client_secret = client_secret
        db.session.add(credentials)
        db.session.commit()


token_service = TokenService()
oauth2_client_credentials_service = Oauth2ClientCredentialsService()
