import time
from uuid import uuid4

import pytest
from authlib.jose import JsonWebKey, Key, JsonWebToken
from cryptography.hazmat.primitives import serialization
from flask.testing import FlaskClient

from application import create_app
from application.database import db
from application.oauth_server.model import SmartService, SmartServiceStatus


@pytest.fixture()
def client(server_key: Key):
    private_key_bytes = get_private_key_as_pem(server_key)

    app = create_app({'TESTING': True,
                      'SQLALCHEMY_DATABASE_URI': "sqlite:////tmp/test.db",
                      'OIDC_SMART_CONFIG_TOKEN_ENDPOINT': 'http://localhost:8080/endpoint',
                      'OIDC_SMART_CONFIG_SIGNING_ALGS': ["RS384", "ES384", "RS512"],
                      'OIDC_JWT_PUBLIC_KEY': server_key.as_pem(),
                      'OIDC_JWT_PRIVATE_KEY': private_key_bytes})
    with app.test_client() as client:
        with app.app_context():
            yield client



@pytest.fixture()
def smart_service(key: Key):
    public_key = key.get_public_key()
    public_key_bytes = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
    smart_service = SmartService(created_by='admin',
                                 client_id=str(uuid4()),
                                 status=SmartServiceStatus.APPROVED,
                                 public_key=public_key_bytes.decode('utf8'))
    db.session.add(smart_service)
    db.session.commit()
    yield smart_service


@pytest.fixture()
def key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


@pytest.fixture()
def server_key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


def test_introspect_client_happy(client: FlaskClient, key: Key, smart_service: SmartService):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.time(),
        "exp": time.time() + 1000,
        "iss": smart_service.client_id,
        "jti": str(uuid4()),
        "aud": client.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, key)
    data = {'token': token}
    rv = client.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert 'active' in rv.json
    assert rv.json['active']


def test_introspect_client_fail_exp(client: FlaskClient, key: JsonWebKey, smart_service: SmartService):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.time(),
        "exp": time.time() - 1000,
        "iss": smart_service.client_id,
        "jti": str(uuid4()),
        "aud": client.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, key)
    data = {'token': token}
    rv = client.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert len(rv.json) == 1
    assert 'active' in rv.json
    assert not rv.json['active']


def test_introspect_client_fail_iss(client: FlaskClient, key: JsonWebKey, smart_service: SmartService):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.time(),
        "exp": time.time() - 1000,
        "jti": str(uuid4()),
        "aud": client.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, key)
    data = {'token': token}
    rv = client.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert len(rv.json) == 1
    assert 'active' in rv.json
    assert not rv.json['active']

def test_introspect_client_fail_enc(client: FlaskClient, key: JsonWebKey, smart_service: SmartService):
    header = {
        "alg": "HS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.time(),
        "exp": time.time() + 1000,
        "iss": smart_service.client_id,
        "jti": str(uuid4()),
        "aud": client.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']
    }
    json_token = JsonWebToken(algorithms=['HS512'])
    token = json_token.encode(header, payload, "shared-secret")
    data = {'token': token}
    rv = client.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert len(rv.json) == 1
    assert 'active' in rv.json
    assert not rv.json['active']


def get_private_key_as_pem(key: Key):
    private_key = key.get_private_key()
    private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.PKCS8,
                                                  encryption_algorithm=serialization.NoEncryption())
    return private_key_bytes

def test_introspect_server_fail_exp(client: FlaskClient, server_key: Key, smart_service: SmartService):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": time.time(),
        "exp": time.time() - 1000,
        "iss": 'http://localhost/',
        "jti": str(uuid4()),
        "aud": client.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, get_private_key_as_pem(server_key))
    data = {'token': token}
    rv = client.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert 'active' in rv.json
    assert not rv.json['active']


