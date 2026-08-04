from unittest import mock
from uuid import uuid4

import pytest
from authlib.jose import JsonWebKey, Key, JsonWebToken
from flask.testing import FlaskClient

from application import create_app
from application.database import db
from application.oauth_server.model import Oauth2Token, SmartService, SmartServiceStatus
from application.oauth_server.service import token_service
from application.utils import get_private_key_as_pem, get_public_key_as_pem
from utils import _client_assertion
from utils import get_now


@pytest.fixture()
def testing_app(server_key: Key):
    private_key_bytes = get_private_key_as_pem(server_key)

    # AUTH_SERVER_ISS is deliberately different from request.url_root ('http://localhost/')
    # and has no trailing slash, mirroring the deployed configuration. This pins the
    # regression where the verifier compared against url_root while tokens were minted
    # with the configured issuer.
    app = create_app({'TESTING': True,
                      'SQLALCHEMY_TRACK_MODIFICATIONS' : False,
                      'SQLALCHEMY_DATABASE_URI': "sqlite:////tmp/test.db",
                      'AUTH_SERVER_ISS': 'https://auth.example.com',
                      'OIDC_SMART_CONFIG_TOKEN_ENDPOINT': 'http://localhost/token',
                      'OIDC_SMART_CONFIG_SIGNING_ALGS': ["RS384", "ES384", "RS512"],
                      'OIDC_JWT_EXP_TIME_ACCESS_TOKEN': 300,
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
                                 public_key=get_public_key_as_pem(foreign_key).decode('utf8'),
                                 fhir_store_device_id=foreign_id)
    db.session.add(smart_service)
    db.session.commit()
    yield smart_service


@pytest.fixture()
def smart_service_client(client_key, client_id):
    smart_service = SmartService(created_by='admin',
                                 client_id=client_id,
                                 status=SmartServiceStatus.APPROVED,
                                 public_key=get_public_key_as_pem(client_key).decode('utf8'),
                                 fhir_store_device_id=client_id)
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
                                 smart_service_foreign: SmartService,
                                 smart_service_client: SmartService,
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
        "aud": f'Device/{smart_service_client.fhir_store_device_id}'
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
    assert not rv.json['active']


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
        "aud": testing_app.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']
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
        "aud": testing_app.application.config['OIDC_SMART_CONFIG_TOKEN_ENDPOINT']
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
        "iss": 'https://auth.example.com',
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


@mock.patch('application.oauth_server.views.fhir_logging_service')
def test_introspect_hti_launch_token_logs_audit_event(mock_logging,
                                                      testing_app: FlaskClient,
                                                      foreign_key: Key,
                                                      smart_service_foreign: SmartService,
                                                      smart_service_client: SmartService,
                                                      client_assertion):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "Patient/123",
        "iat": get_now(),
        "exp": get_now(300),
        "iss": smart_service_foreign.client_id,
        "jti": str(uuid4()),
        "aud": f'Device/{smart_service_client.fhir_store_device_id}'
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, foreign_key)
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})

    assert rv.json['active']
    mock_logging.register_token_introspection.assert_called_once()
    call_args = mock_logging.register_token_introspection.call_args
    assert call_args.args[0] == "Patient/123"
    assert call_args.args[1] == smart_service_client.client_id
    assert call_args.args[2] == "0"
    assert call_args.args[3]['X-Trace-Id'] == payload['jti']


@mock.patch('application.oauth_server.views.fhir_logging_service')
def test_introspect_invalid_hti_token_logs_failure_audit_event(mock_logging,
                                                      testing_app: FlaskClient,
                                                      foreign_key: Key,
                                                      smart_service_foreign: SmartService,
                                                      smart_service_client: SmartService,
                                                      client_assertion):
    header = {
        "alg": "RS512",
        "typ": "JWT"
    }
    payload = {
        "sub": "Patient/123",
        "iat": get_now(),
        "exp": get_now(-1000),
        "iss": smart_service_foreign.client_id,
        "jti": str(uuid4()),
        "aud": f'Device/{smart_service_client.fhir_store_device_id}'
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, foreign_key)
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})

    assert not rv.json['active']
    mock_logging.register_token_introspection.assert_called_once()
    call_args = mock_logging.register_token_introspection.call_args
    assert call_args.args[0] == "Patient/123"
    assert call_args.args[1] == smart_service_client.client_id
    assert call_args.args[2] == "4"


def _issue_access_token(testing_app: FlaskClient, client_key: Key, client_id: str) -> str:
    """Obtain a real access token through the client_credentials endpoint."""
    rv = testing_app.post('/oauth2/token', data={
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': _client_assertion(testing_app, client_key, client_id)})
    assert rv.status_code == 200, rv.data
    return rv.json['access_token']


def _issue_id_token(testing_app: FlaskClient, client_id: str, subject: str) -> str:
    """Mint a real id_token through TokenService, the way the launch flow does."""
    oauth2_token = Oauth2Token()
    oauth2_token.client_id = client_id
    oauth2_token.subject = subject
    with testing_app.application.test_request_context():
        return token_service.get_id_token(oauth2_token)


def _introspect(testing_app: FlaskClient, client_key: Key, client_id: str, token: str):
    return testing_app.post('/oauth2/introspect',
                            data={'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                                  'client_assertion': _client_assertion(testing_app, client_key, client_id),
                                  'token': token},
                            headers={'Accept': 'application/javascript'})


@mock.patch('application.oauth_server.views.fhir_logging_service')
def test_introspect_real_access_token_is_active(mock_logging,
                                                testing_app: FlaskClient,
                                                client_key: Key,
                                                smart_service_client: SmartService):
    access_token = _issue_access_token(testing_app, client_key, smart_service_client.client_id)

    rv = _introspect(testing_app, client_key, smart_service_client.client_id, access_token)

    assert rv.json['active']
    assert rv.json['azp'] == smart_service_client.client_id
    # The echoed iss is the minted claim: this pins that minting uses the configured issuer
    # rather than request.url_root, so minting and verifying cannot drift there together.
    assert rv.json['iss'] == 'https://auth.example.com'
    mock_logging.register_token_introspection.assert_not_called()


@mock.patch('application.oauth_server.views.fhir_logging_service')
def test_introspect_real_id_token_is_active(mock_logging,
                                            testing_app: FlaskClient,
                                            client_key: Key,
                                            smart_service_client: SmartService):
    id_token = _issue_id_token(testing_app, smart_service_client.client_id, 'RelatedPerson/123')

    rv = _introspect(testing_app, client_key, smart_service_client.client_id, id_token)

    assert rv.json['active']
    assert rv.json['sub'] == 'RelatedPerson/123'
    assert rv.json['iss'] == 'https://auth.example.com'
    mock_logging.register_token_introspection.assert_not_called()


@mock.patch('application.oauth_server.views.fhir_logging_service')
def test_introspect_access_token_is_repeatable(mock_logging,
                                               testing_app: FlaskClient,
                                               client_key: Key,
                                               smart_service_client: SmartService):
    """A resource server introspects the same token on every request - it must not be single use."""
    access_token = _issue_access_token(testing_app, client_key, smart_service_client.client_id)

    first = _introspect(testing_app, client_key, smart_service_client.client_id, access_token)
    second = _introspect(testing_app, client_key, smart_service_client.client_id, access_token)

    assert first.json['active']
    assert second.json['active']


def test_introspect_malformed_token_is_inactive(testing_app: FlaskClient,
                                                client_key: Key,
                                                smart_service_client: SmartService):
    rv = _introspect(testing_app, client_key, smart_service_client.client_id, 'not-a-jwt')

    assert rv.status_code == 200
    assert not rv.json['active']

