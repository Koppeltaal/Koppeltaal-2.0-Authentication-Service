from time import time
from uuid import uuid4

from authlib.jose import Key, JsonWebKey
from authlib.jose import jwt
from flask import request, current_app

from application.oidc_server.model import Oauth2Session, Oauth2Token


class TokenService:
    def get_id_token(self, oauth2_token: Oauth2Token) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], oauth2_token.client_id,
                                   sub=oauth2_token.subject, email=oauth2_token.email,
                                   given_name=oauth2_token.name_given, family_name=oauth2_token.name_family)

    def get_access_token(self, oauth2_token: Oauth2Token, oauth_session: Oauth2Session) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], 'fhir-server', type='access',
                                   sub=oauth2_token.subject, scope=oauth_session.scope)

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

token_service = TokenService()
