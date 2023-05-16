import base64
import string
import time
from hashlib import sha256
from random import choice
from unittest import mock
from urllib.parse import urlencode
from uuid import uuid4

import jwt
import pytest
from authlib.jose import JsonWebKey, Key
from flask.testing import FlaskClient

from application import create_app
from application.database import db
from application.oauth_server.model import SmartService, SmartServiceStatus, IdentityProvider
from application.utils import get_private_key_as_pem, get_public_key_as_pem
from utils import _client_assertion, _hti_token, _get_params_from_redirect


@pytest.fixture()
def testing_app(server_key: Key):
    private_key_bytes = get_private_key_as_pem(server_key)

    app = create_app({'TESTING': True,
                      'SQLALCHEMY_TRACK_MODIFICATIONS' : False,
                      'SQLALCHEMY_DATABASE_URI': "sqlite:////tmp/test.db",
                      'OIDC_SMART_CONFIG_TOKEN_ENDPOINT': 'http://localhost:8080/endpoint',
                      'OIDC_JWT_EXP_TIME_ACCESS_TOKEN': 60,
                      'FHIR_CLIENT_SERVERURL': 'http://fhir-server.com/url',
                      'IDP_AUTHORIZE_CLIENT_ID': str(uuid4()),
                      'IDP_AUTHORIZE_REDIRECT_URL': 'http://localhost:5000/idp/oidc/code',
                      'IDP_AUTHORIZE_ENDPOINT': 'http://localhost:5000/idp/authorize',
                      'IDP_TOKEN_ENDPOINT': 'http://localhost:5000/idp/token',
                      'IDP_AUTHORIZE_CLIENT_SECRET': str(uuid4()),
                      'SMART_BACKEND_SERVICE_CLIENT_ID': str(uuid4()),
                      'OIDC_SMART_CONFIG_SIGNING_ALGS': ["RS384", "ES384", "RS512"],
                      'OIDC_JWT_PUBLIC_KEY': server_key.as_pem(),
                      'OIDC_JWT_PRIVATE_KEY': private_key_bytes})
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture()
def client_id():
    return str(uuid4())


@pytest.fixture()
def client_id_idp() -> str:
    yield str(uuid4())


@pytest.fixture()
def portal_id():
    return str(uuid4())


@pytest.fixture()
def user_id():
    return f'Practitioner/{str(uuid4())}'


@pytest.fixture()
def patient_id():
    return f'Patient/{str(uuid4())}'


@pytest.fixture()
def resource_id():
    return f'Task/{str(uuid4())}'

@pytest.fixture()
def smart_service_client(testing_app: FlaskClient, client_key: Key, client_id: str):
    public_key_bytes = get_public_key_as_pem(client_key)
    smart_service_client = SmartService(created_by='admin',
                                        client_id=client_id,
                                        status=SmartServiceStatus.APPROVED,
                                        public_key=public_key_bytes.decode('utf8'),
                                        fhir_store_device_id=str(uuid4()))
    db.session.add(smart_service_client)
    db.session.commit()
    yield smart_service_client


@pytest.fixture()
def smart_service_portal(portal_key: Key, portal_id: str):
    public_key_bytes = get_public_key_as_pem(portal_key)
    smart_service_portal = SmartService(created_by='admin',
                                        client_id=portal_id,
                                        status=SmartServiceStatus.APPROVED,
                                        public_key=public_key_bytes.decode('utf8'))
    db.session.add(smart_service_portal)
    db.session.commit()
    yield smart_service_portal


@pytest.fixture()
def smart_service_custom_idp(identity_provider, client_key: Key, client_id_idp: str):
    public_key_bytes = get_public_key_as_pem(client_key)
    smart_service_custom_idp = SmartService(created_by='admin',
                                        client_id=client_id_idp,
                                        status=SmartServiceStatus.APPROVED,
                                        public_key=public_key_bytes.decode('utf8'),
                                        fhir_store_device_id=str(uuid4()),
                                        patient_idp=identity_provider.id,
                                        practitioner_idp=identity_provider.id)
    print("custom idp met client_id: ", client_id_idp)
    print("custom idp met client_id: ", smart_service_custom_idp.client_id)
    db.session.add(smart_service_custom_idp)
    db.session.commit()
    yield smart_service_custom_idp


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
def portal_key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


@pytest.fixture()
def code_verifier():
    length = 128
    letters = f'{string.ascii_letters}-._~'
    return ''.join(choice(letters) for i in range(length))


@pytest.fixture()
def code_challenge(code_verifier):
    return base64.b64encode(sha256(code_verifier.encode('ascii')).digest()).decode('ascii')


@pytest.fixture()
def custom_idp_location():
    return 'https://unit.test/idp'


@pytest.fixture()
def identity_provider():
    identity_provider = IdentityProvider(created_by='admin',
                                         client_id='client-id',
                                         client_secret='top-secret',
                                         username_attribute='sub',
                                         endpoint='http://unit.test/.well-known/openid-configuration')
    db.session.add(identity_provider)
    db.session.commit()
    yield identity_provider

def test_client_credentials_happy(testing_app: FlaskClient, foreign_key, client_key: Key, client_id: str,
                                  smart_service_client: SmartService):
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': _client_assertion(testing_app, client_key, client_id),
            'grant_type': 'client_credentials'}

    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 200
    response_data = rv.json
    access_token = response_data.get('access_token')
    assert access_token is not None
    jwt_decode = jwt.decode(access_token, testing_app.application.config['OIDC_JWT_PUBLIC_KEY'],
                            algorithms=['RS512'],
                            audience=['fhir-server'])
    assert jwt_decode['azp'] == smart_service_client.client_id


def _test_authorization_code_happy_post(url, data, headers):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = True

        def json(self):
            return self.json_data

    data = {'sub': 'user',
            'email': 'test@example.com'}
    id_token = jwt.encode(data, key=None, algorithm='none')
    return MockResponse({'id_token': id_token}, 200)


def _test_authorization_code_happy_get(url, headers):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = True

        def json(self):
            return self.json_data

    data = {'identifier': [{'value': 'test@example.com'}]}
    return MockResponse(data, 200)


def _test_fetch_openid_configuration(url):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = True

        def json(self):
            return self.json_data

    data = {'authorization_endpoint': 'https://unit.test/idp'}
    return MockResponse(data, 200)


@mock.patch('requests.post', side_effect=_test_authorization_code_happy_post)
@mock.patch('requests.get', side_effect=_test_authorization_code_happy_get)
def test_authorization_code_happy_without_verifier(mock1, mock2, testing_app: FlaskClient, foreign_key,
                                                   client_key: Key,
                                                   portal_key: Key,
                                                   client_id: str,
                                                   portal_id: str,
                                                   user_id: str,
                                                   patient_id: str,
                                                   resource_id: str,
                                                   smart_service_client: SmartService,
                                                   smart_service_portal: SmartService):
    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': 'https://module.local./back',
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')
    token_code, token_state = _get_params_from_redirect(redirect_resp, 'code', 'state')

    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': _client_assertion(testing_app, client_key, client_id),
            'code': token_code,
            'state': token_state,
            'redirect_uri': 'https://module.local./back',
            'grant_type': 'authorization_code'}

    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 200
    response_data = rv.json
    access_token = response_data.get('access_token')
    assert access_token is not None
    assert access_token == 'NOOP'
    assert response_data['sub'] == user_id
    assert response_data['patient'] == patient_id
    assert response_data['resource'] == resource_id

# TODO: Fix unit test where the openid-configuration is properly mocked
# @mock.patch('requests.post', side_effect=_test_authorization_code_happy_post)
# @mock.patch('requests.get', side_effect=_test_authorization_code_happy_get)
# @mock.patch('json.load', side_effect=_test_fetch_openid_configuration)
# def test_authorization_code_with_custom_idp(mock1, mock2, testing_app: FlaskClient, foreign_key,
#                                             client_key: Key,
#                                             portal_key: Key,
#                                             client_id: str,
#                                             portal_id: str,
#                                             user_id: str,
#                                             patient_id: str,
#                                             resource_id: str,
#                                             smart_service_client: SmartService,
#                                             smart_service_portal: SmartService,
#                                             smart_service_custom_idp: SmartService,
#                                             custom_idp_location: str):
#     state = str(uuid4())
#     data = {'scope': 'launch fhirUser openid',
#             'redirect_uri': 'https://module.local./back',
#             'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
#             'client_id': smart_service_custom_idp.client_id,
#             'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id),
#             'state': state}
#     authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
#
#     idp_redirect_location = authorize_resp.get_wsgi_headers({})['Location']
#
#     assert idp_redirect_location.startswith(custom_idp_location)

@mock.patch('requests.post', side_effect=_test_authorization_code_happy_post)
@mock.patch('requests.get', side_effect=_test_authorization_code_happy_get)
def test_authorization_code_happy_with_verifier(mock1, mock2, testing_app: FlaskClient, foreign_key,
                                                client_key: Key,
                                                portal_key: Key,
                                                client_id: str,
                                                portal_id: str,
                                                user_id: str,
                                                patient_id: str,
                                                resource_id: str,
                                                code_challenge: str,
                                                code_verifier: str,
                                                smart_service_client: SmartService,
                                                smart_service_portal: SmartService):
    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': 'https://module.local./back',
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')
    token_code, token_state = _get_params_from_redirect(redirect_resp, 'code', 'state')

    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': _client_assertion(testing_app, client_key, client_id),
            'code': token_code,
            'state': token_state,
            'code_verifier': code_verifier,
            'redirect_uri': 'https://module.local./back',
            'grant_type': 'authorization_code'}

    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 200
    response_data = rv.json
    access_token = response_data.get('access_token')
    assert access_token is not None
    assert access_token == 'NOOP'
    assert response_data['sub'] == user_id
    assert response_data['patient'] == patient_id
    assert response_data['resource'] == resource_id


def test_client_credentials_exp(testing_app: FlaskClient, foreign_key, client_key: Key, client_id: str,
                                smart_service_client: SmartService):
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': _client_assertion(testing_app, client_key, client_id,
                                                  extra_payload={'exp': str(int(time.time() - 1))}),
            'grant_type': 'client_credentials'}
    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 401


def test_client_credentials_wrong_status_1(testing_app: FlaskClient, foreign_key, client_key: Key, client_id: str,
                                           smart_service_client: SmartService):
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': _client_assertion(testing_app, client_key, client_id),
            'grant_type': 'client_credentials'}
    smart_service_client.status = 'PENDING'
    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 401


def test_client_credentials_wrong_status_2(testing_app: FlaskClient, foreign_key, client_key: Key, client_id: str,
                                           smart_service_client: SmartService):
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': _client_assertion(testing_app, client_key, client_id),
            'grant_type': 'client_credentials'}
    smart_service_client.status = 'REJECTED'
    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 401


def test_client_credentials_wrong_grant_type(testing_app: FlaskClient, foreign_key, client_key: Key, client_id: str,
                                             smart_service_client: SmartService):
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': _client_assertion(testing_app, client_key, client_id),
            'grant_type': 'x'}
    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 400


def test_client_credentials_wrong_client_assertion_type(testing_app: FlaskClient, foreign_key, client_key: Key,
                                                        client_id: str,
                                                        smart_service_client: SmartService):
    data = {'client_assertion_type': 'x',
            'client_assertion': _client_assertion(testing_app, client_key, client_id),
            'grant_type': 'client_credentials'}
    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 401


def test_client_credentials_wrong_assertion(testing_app: FlaskClient, foreign_key, client_key: Key, client_id: str,
                                            smart_service_client: SmartService):
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': 'x',
            'grant_type': 'client_credentials'}
    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 401
