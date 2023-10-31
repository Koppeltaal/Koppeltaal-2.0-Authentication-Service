#  Copyright (c) Stichting Koppeltaal 2021.
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
import logging
from typing import Dict, Any, Optional

import jwt as pyjwt
from flask import current_app, request
from jwt import DecodeError, InvalidSignatureError

from application.jwks.service import keypair_service
from application.oauth_server.jwks_client import CacheHeaderPyJWKClient
from application.oauth_server.model import SmartService, SmartServiceStatus
from application.oauth_server.service import LAUNCH_SCOPE_ALLOWED

logger = logging.getLogger('verifiers')
consumed_jti_tokens = []


def verify_token(encoded_token: str, auth_client_id: str) -> Optional[Dict[str, Any]]:
    unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
    iss = unverified_decoded_jwt.get('iss', '')
    aud = unverified_decoded_jwt.get('aud', '')

    token_endpoint = _get_token_endpoint()
    is_client_id = _exists_smart_service(iss)
    if iss == request.url_root and aud == 'fhir-service':
        logger.info("verify_token matched to access_token_verifier")
        return access_token_verifier.verify_and_get_token(encoded_token)
    elif is_client_id and aud == token_endpoint:
        logger.info("verify_token matched to client_credentials_verifier")
        return client_credentials_verifier.verify_and_get_token(encoded_token, auth_client_id)
    elif is_client_id and aud.startswith('Device/'):
        logger.info("verify_token matched to hti_token_verifier")
        return hti_token_verifier.verify_and_get_token(encoded_token, auth_client_id)

    logger.warning(f"Cannot verify token for issuer [{iss}] and aud [{aud}] - it did not match any condition matched to a verifier")
    return


class ClientCredentialsTokenVerifier:
    """
    This class validates tokens issued by a registered application as smart_service.
    """

    def verify_and_get_token(self, encoded_token, auth_client_id=None):
        try:
            unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        except DecodeError as e:
            logger.warning(f"Failed to decode JWT: {e}")
            return

        if not _verify_required_fields(unverified_decoded_jwt, ['iss', 'aud', 'jti']):
            return

        if not _verify_jti(unverified_decoded_jwt):
            return

        client_id = unverified_decoded_jwt['iss']
        smart_service: SmartService = get_smart_service(client_id)

        if not smart_service or smart_service.status != SmartServiceStatus.APPROVED:
            logger.warning(
                f"Discontinuing request for client_id {client_id}, smart service not found or status not approved")
            return

        aud = unverified_decoded_jwt['aud']
        if not self._verify_aud(aud, auth_client_id):
            logger.warning(f'Failed to verify the aud value ({aud}) of the JWT token.')
            return

        try:
            if smart_service.jwks_endpoint:
                return _decode_with_jwks(smart_service, aud, encoded_token)
            elif smart_service.public_key:
                return _decode_with_public_key(smart_service, aud, encoded_token)
            else:
                logger.error(f"No JWKS or Public Key found on smart service with client_id {client_id}", )
        except InvalidSignatureError as ise:
            logger.warning(f"Invalid signature for client_id {client_id}, exception {ise}")
            return
        except Exception as e:
            logger.warning(
                f"Something went wrong whilst trying to decode the JWT for client_id {client_id}, exception {e}")
            return

    @staticmethod
    def _verify_aud(aud: str, auth_client_id):
        token_endpoint = _get_token_endpoint()
        if token_endpoint == aud:  # Check if the audience is the auth service itself.
            return True

        logger.warning(f'Unexpected aud in token: {aud}, expected: {token_endpoint}')
        return False


class HtiTokenVerifier(ClientCredentialsTokenVerifier):
    def __init__(self):
        pass

    @staticmethod
    def validate_and_parse_launch_scope(scope: str, encoded_token: str):
        scopes = scope.split()
        for allowed_set in LAUNCH_SCOPE_ALLOWED:
            if set(allowed_set) == set(scopes):
                return scopes

        return None

    @staticmethod
    def _verify_aud(aud: str, auth_client_id):
        if aud.startswith("Device/"):  # Check if the audience is the Device/123 reference.
            smart_service: SmartService = SmartService.query.filter_by(fhir_store_device_id=aud.split("/")[1]).first()
            if smart_service and smart_service.client_id == auth_client_id:
                return True

            logger.warning(
                f'Unable to find a smart service {aud} with client id {auth_client_id}')
        return False


class AccessTokenVerifier():
    def verify_and_get_token(self, encoded_token):
        try:
            unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
        except DecodeError as e:
            logger.warning(f"Failed to decode JWT: {e}")
            return

        if not _verify_required_fields(unverified_decoded_jwt, ['iss', 'aud', 'jti']):
            return

        if not _verify_jti(unverified_decoded_jwt):
            return

        iss = unverified_decoded_jwt['iss']
        if iss != request.url_root:
            logger.warning("JWT doesn't contain self as iss value")
            return

        try:
            return _decode_with_own_key(encoded_token)

        except InvalidSignatureError as ise:
            logger.warning(f"Invalid signature validating own key, exception {ise}")
            return
        except Exception as e:
            logger.warning(
                f"Something went wrong whilst trying to decode the JWT, exception {e}")
            return


def _decode_with_jwks(smart_service, aud, encoded_token) -> Dict[str, Any]:
    logger.info(f'Fetching endpoint: "{smart_service.jwks_endpoint}" for client_id: {smart_service.client_id}')
    jwks_client = CacheHeaderPyJWKClient(smart_service.jwks_endpoint)
    signing_key = jwks_client.get_signing_key_from_jwt(encoded_token)
    decoded_jwt = pyjwt.decode(encoded_token, signing_key.key,
                               algorithms=current_app.config['OIDC_SMART_CONFIG_SIGNING_ALGS'],
                               audience=aud)
    logger.info(f'JWT for client_id {smart_service.client_id} is decoded by JWKS - valid key')
    return decoded_jwt


def _verify_required_fields(unverified_decoded_jwt, required_fields):
    for field in required_fields:
        if field not in unverified_decoded_jwt:
            logger.warning(f"JWT doesn't contain a value for field {field}")
            return False
    return True


def _decode_with_own_key(encoded_token):
    _, public_key = keypair_service.get_keypair()
    decoded_jwt = pyjwt.decode(encoded_token, public_key.as_pem(),
                               algorithms=current_app.config[
                                   'OIDC_SMART_CONFIG_SIGNING_ALGS'],
                               options={'verify_aud': False})  # TODO: check if correct

    logger.info(f'JWT signed by self is decoded by JWKS - valid key')
    return decoded_jwt


def _decode_with_public_key(smart_service, aud, encoded_token) -> Dict[str, Any]:
    public_key = smart_service.public_key

    if not public_key.startswith("-----BEGIN PUBLIC KEY-----"):
        logger.debug(
            f"public key for client_id {smart_service.client_id} didn't contain -----BEGIN PUBLIC KEY-----, injecting start and end tags")
        public_key = f'-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----'

    decoded_jwt = pyjwt.decode(encoded_token, public_key,
                               algorithms=["RS512"],  ## TODO: check with spec
                               audience=aud)

    logger.info(f'JWT for client_id {smart_service.client_id} is decoded by PUBLIC KEY - valid key')
    return decoded_jwt


def _verify_jti(unverified_decoded_jwt):
    if 'jti' not in unverified_decoded_jwt:
        logger.warning("JWT doesn't contain a jti value")
        return False
    if unverified_decoded_jwt['jti'] in consumed_jti_tokens:
        logger.warning(f"JWT is being replayed - jti {unverified_decoded_jwt['jti']} is already consumed")
        return False

    consumed_jti_tokens.append(unverified_decoded_jwt['jti'])
    return True


def get_smart_service(client_id):
    smart_service = SmartService.query.filter_by(client_id=client_id).first()
    logger.info(f'Matched issuer {client_id} to smart service {smart_service}')

    return smart_service


def _exists_smart_service(client_id):
    return SmartService.query.filter_by(client_id=client_id).count() > 0


def _get_token_endpoint():
    return current_app.config('OIDC_SMART_CONFIG_TOKEN_ENDPOINT', request.base_url + 'oauth2/token')


client_credentials_verifier = ClientCredentialsTokenVerifier()
access_token_verifier = AccessTokenVerifier()
hti_token_verifier = HtiTokenVerifier()
