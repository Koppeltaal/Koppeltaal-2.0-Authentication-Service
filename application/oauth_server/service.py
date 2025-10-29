#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
import logging
from base64 import urlsafe_b64decode
from calendar import timegm
from datetime import datetime, timezone
from hashlib import sha256
from uuid import uuid4

from authlib.jose import jwt
from flask import request, current_app

from application.jwks.service import keypair_service
from application.oauth_server.model import Oauth2Token

logger = logging.getLogger('oauth_service')
logger.setLevel(logging.DEBUG)


LAUNCH_SCOPE_DEFAULT = 'launch openid fhirUser'
LAUNCH_SCOPE_ALLOWED = [
    # ['launch'],
    ['launch', 'openid', 'fhirUser']
]


def get_timestamp_now():
    return timegm(datetime.now(tz=timezone.utc).utctimetuple())


class TokenAuthorizationCodeService:
    def check_challenge(self, code_challenge: str, code_verifier: str, code_challenge_method: str) -> bool:
        if code_challenge:
            assert code_challenge_method == 'S256'
            assert code_verifier is not None
            expected_challenge = sha256(code_verifier.encode('ascii')).digest()
            return self._base_64_url_decode(code_challenge.encode('ascii')) == expected_challenge

        return True  # TODO: once implemented in all applications this should return false

    def _base_64_url_decode(self, base64Url):
        padding = b'=' * (4 - (len(base64Url) % 4))
        return urlsafe_b64decode(base64Url + padding)


class TokenService:
    def get_id_token(self, oauth2_token: Oauth2Token) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'],
                                   oauth2_token.client_id,
                                   sub=oauth2_token.subject,
                                   azp=oauth2_token.client_id,
                                   fhirUser=oauth2_token.subject)

    def get_access_token(self, oauth2_token: Oauth2Token, scope: str) -> str:
        return self._get_jwt_token(current_app.config['OIDC_JWT_EXP_TIME_ACCESS_TOKEN'], 'fhir-server',
                                   type='access',
                                   sub=oauth2_token.subject,
                                   scope=scope,
                                   azp=oauth2_token.client_id)

    def get_system_access_token(self) -> str:
        return self._get_jwt_token(120, 'fhir-server',
                                   type='access',
                                   scope='system/*.cruds',
                                   sub=current_app.config['SMART_BACKEND_SERVICE_CLIENT_ID'],
                                   azp=current_app.config['SMART_BACKEND_SERVICE_CLIENT_ID'])

    def get_refresh_token(self) -> str:
        return str(uuid4())

    def _get_jwt_token(self, expiry: int, aud: str, type: str = None, sub: str = None, email: str = None,
                       given_name: str = None, family_name: str = None, scope: str = None, azp: str = None, fhirUser: str = None) -> str:
        private_key, public_key = keypair_service.get_keypair()
        now = get_timestamp_now()
        payload = {
            'iss': current_app.config.get('AUTH_SERVER_ISS', request.url_root),
            'aud': aud,
            'iat': now,
            'nbf': now,
            'exp': now + expiry,
            'nonce': str(uuid4()),
            'jti': str(uuid4())}
        if type is not None:
            payload['type'] = type

        if sub is not None:
            payload['sub'] = sub

        if fhirUser is not None:
            payload['fhirUser'] = fhirUser

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





token_service = TokenService()
token_authorization_code_service = TokenAuthorizationCodeService()

"""
headease-koppeltaal-koppeltaal-2-0-smart-service-testsuite-staging.koppeltaal.headease.nl
"""
