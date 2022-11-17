from datetime import datetime, timedelta
from typing import Dict
from urllib.parse import urlparse, parse_qsl
from uuid import uuid4

import jwt
from authlib.jose import Key
from flask.testing import FlaskClient

from application.utils import get_private_key_as_pem


def _client_assertion(testing_app: FlaskClient, client_key: Key, client_id: str, extra_payload: Dict[str, str] = None):
    payload = {'iss': client_id,
               'sub' : client_id,
               'aud': testing_app.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT'],
               'iat': datetime.now(),
               'exp': datetime.now() + timedelta(minutes=5),
               'jti': str(uuid4())}
    if extra_payload:
        payload.update(extra_payload)
    return jwt.encode(payload, get_private_key_as_pem(client_key), algorithm="RS512")


def _hti_token(testing_app: FlaskClient, portal_key: Key, portal_id: str, user_id: str):
    payload = {'iss': portal_id,
               'jti': str(uuid4()),
               'sub': user_id,
               'aud': testing_app.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']}
    return jwt.encode(payload, get_private_key_as_pem(portal_key), algorithm="RS512")


def _get_params_from_redirect(response, *keys):
    redirect_location = urlparse(response.headers.get("Location"))
    redirect_q = dict(parse_qsl(redirect_location.query))
    rv = []
    for key in keys:
        rv.append(redirect_q[key])

    if len(rv) == 1:
        return rv[0]

    return tuple(rv)
