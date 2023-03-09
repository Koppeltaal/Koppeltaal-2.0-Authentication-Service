from uuid import uuid4

import pytest
from authlib.jose import JsonWebKey, Key, JsonWebToken
from flask.testing import FlaskClient

from application import create_app
from application.database import db
from application.oauth_server.model import SmartService, SmartServiceStatus
from application.utils import get_private_key_as_pem, get_public_key_as_pem
from utils import _client_assertion
from utils import get_now


@pytest.fixture()
def testing_app(server_key: Key):
    private_key_bytes = get_private_key_as_pem(server_key)

    app = create_app({'TESTING': True,
                      'SQLALCHEMY_TRACK_MODIFICATIONS' : False,
                      'SQLALCHEMY_DATABASE_URI': "sqlite:////tmp/test.db",
                      'OIDC_SMART_CONFIG_TOKEN_ENDPOINT': 'http://localhost:8080/endpoint',
                      'OIDC_SMART_CONFIG_SIGNING_ALGS': ["RS384", "ES384", "RS512"],
                      'OIDC_JWT_PUBLIC_KEY': server_key.as_pem(),
                      'OIDC_JWT_PRIVATE_KEY': private_key_bytes})
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture()
def smart_service_foreign(foreign_key, foreign_id):
    smart_service = SmartService(created_by='admin',
                                 client_id=foreign_id,
                                 status=SmartServiceStatus.APPROVED,
                                 public_key=get_public_key_as_pem(foreign_key).decode('utf8'))
    db.session.add(smart_service)
    db.session.commit()
    yield smart_service


@pytest.fixture()
def smart_service_client(client_key, client_id):
    smart_service = SmartService(created_by='admin',
                                 client_id=client_id,
                                 status=SmartServiceStatus.APPROVED,
                                 public_key=get_public_key_as_pem(client_key).decode('utf8'))
    db.session.add(smart_service)
    db.session.commit()
    yield smart_service


@pytest.fixture()
def foreign_key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


@pytest.fixture()
def server_key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


@pytest.fixture()
def client_key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


@pytest.fixture()
def client_assertion(testing_app, client_key, smart_service_client):
    yield _client_assertion(testing_app, client_key, smart_service_client.client_id)


@pytest.fixture()
def client_id() -> str:
    yield str(uuid4())


@pytest.fixture()
def foreign_id() -> str:
    yield str(uuid4())


def test_introspect_client_happy(testing_app: FlaskClient,
                                 foreign_key: Key,
                                 smart_service_foreign,
                                 smart_service_client,
                                 client_assertion):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": get_now(),
        "exp": get_now(300),
        "iss": smart_service_foreign.client_id,
        "jti": str(uuid4()),
        "aud": smart_service_client.client_id
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, foreign_key)
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert 'active' in rv.json
    assert rv.json['active']

def test_introspect_client_fail_audience(testing_app: FlaskClient,
                                 foreign_key: Key,
                                 smart_service_foreign,
                                 client_assertion):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": get_now(),
        "exp": get_now(300),
        "iss": smart_service_foreign.client_id,
        "jti": str(uuid4()),
        "aud": 'faalhaas'
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, foreign_key)
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert 'active' in rv.json
    assert rv.json['active']


def test_introspect_client_fail_exp(testing_app: FlaskClient, foreign_key, smart_service_foreign, smart_service_client, client_assertion):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": get_now(),
        "exp": get_now(-1000),
        "iss": smart_service_foreign.client_id,
        "jti": str(uuid4()),
        "aud": smart_service_client.client_id
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, foreign_key)
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert len(rv.json) == 1
    assert 'active' in rv.json
    assert not rv.json['active']


def test_introspect_client_fail_iss(testing_app: FlaskClient, foreign_key, smart_service_foreign, smart_service_client, client_assertion):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": get_now(),
        "exp": get_now(-1000),
        "jti": str(uuid4()),
        "aud": smart_service_client.client_id
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, foreign_key)
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert len(rv.json) == 1
    assert 'active' in rv.json
    assert not rv.json['active']


def test_introspect_client_fail_enc(testing_app: FlaskClient, foreign_key: Key, smart_service_foreign, smart_service_client,
                                    client_assertion):
    header = {
        "alg": "HS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": get_now(),
        "exp": get_now(300),
        "iss": smart_service_foreign.client_id,
        "jti": str(uuid4()),
        "aud": smart_service_client.client_id
    }
    json_token = JsonWebToken(algorithms=['HS512'])
    token = json_token.encode(header, payload, "shared-secret")
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert len(rv.json) == 1
    assert 'active' in rv.json
    assert not rv.json['active']


def test_introspect_server_fail_exp(testing_app: FlaskClient, server_key: Key, smart_service_foreign, smart_service_client, client_assertion):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": get_now(),
        "exp": get_now(-1000),
        "iss": 'http://localhost/',
        "jti": str(uuid4()),
        "aud": smart_service_client.client_id
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, get_private_key_as_pem(server_key))
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})
    assert 'active' in rv.json
    assert not rv.json['active']
