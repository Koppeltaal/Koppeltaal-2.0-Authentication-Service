import base64
import string
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
from application.oauth_server.model import SmartService, SmartServiceStatus, IdentityProvider, AllowedRedirect
from application.utils import get_private_key_as_pem, get_public_key_as_pem
from utils import _client_assertion, _hti_token, _get_params_from_redirect


@pytest.fixture()
def testing_app(server_key: Key):
    private_key_bytes = get_private_key_as_pem(server_key)

    app = create_app({'TESTING': True,
                      'SQLALCHEMY_TRACK_MODIFICATIONS': False,
                      'SQLALCHEMY_DATABASE_URI': "sqlite:////tmp/test.db",
                      'OIDC_SMART_CONFIG_TOKEN_ENDPOINT': 'http://localhost/token',
                      'OIDC_JWT_EXP_TIME_ACCESS_TOKEN': 60,
                      'FHIR_CLIENT_SERVERURL': 'http://fhir-server.com/url',
                      'AUTH_SERVER_ISS': 'http://issuer.com',
                      'IDP_AUTHORIZE_CLIENT_ID': str(uuid4()),
                      'IDP_AUTHORIZE_REDIRECT_URL': 'http://localhost:5000/idp/oidc/code',
                      'IDP_AUTHORIZE_ENDPOINT': 'http://localhost:5000/idp/authorize',
                      'IDP_TOKEN_ENDPOINT': 'http://localhost:5000/idp/token',
                      'IDP_AUTHORIZE_CLIENT_SECRET': str(uuid4()),
                      'SMART_BACKEND_SERVICE_CLIENT_ID': str(uuid4()),
                      'SMART_BACKEND_SERVICE_DEVICE_ID': 'Device/' + str(uuid4()),
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
def portal_id():
    return str(uuid4())


@pytest.fixture()
def user_id():
    return f'RelatedPerson/{str(uuid4())}'


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
                                        fhir_store_device_id=client_id)
    db.session.add(smart_service_client)
    db.session.commit()
    yield smart_service_client


@pytest.fixture()
def smart_service_portal(portal_key: Key, portal_id: str):
    public_key_bytes = get_public_key_as_pem(portal_key)
    smart_service_portal = SmartService(created_by='admin',
                                        client_id=portal_id,
                                        status=SmartServiceStatus.APPROVED,
                                        public_key=public_key_bytes.decode('utf8'),
                                        fhir_store_device_id=portal_id)
    db.session.add(smart_service_portal)
    db.session.commit()
    yield smart_service_portal


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
def allowed_redirect(smart_service_client):
    allowed_redirect = AllowedRedirect(smart_service_id=smart_service_client.id,
                                       url="http://unit.test")
    db.session.add(allowed_redirect)
    db.session.commit()
    yield allowed_redirect


# Fixtures for RelatedPerson and CareTeam scenarios
@pytest.fixture()
def inactive_related_person(user_id, patient_id):
    return {
        'resourceType': 'RelatedPerson',
        'id': user_id.split('/')[-1],
        'patient': {'reference': patient_id},
        'active': False,
        'identifier': [{'value': 'test@example.com'}]
    }

@pytest.fixture()
def active_related_person(user_id, patient_id):
    return {
        'resourceType': 'RelatedPerson',
        'id': user_id.split('/')[-1],
        'patient': {'reference': patient_id},
        'active': True,
        'identifier': [{'value': 'test@example.com'}]
    }

@pytest.fixture()
def related_person_with_different_identifier(user_id, patient_id):
    return {
        'resourceType': 'RelatedPerson',
        'id': user_id.split('/')[-1],
        'patient': {'reference': patient_id},
        'active': True,
        'identifier': [{'value': 'different@example.com'}]
    }

@pytest.fixture()
def related_person_with_different_patient(user_id):
    return {
        'resourceType': 'RelatedPerson',
        'id': user_id.split('/')[-1],
        'patient': {'reference': 'Patient-some-other-patient-id'},
        'active': True,
        'identifier': [{'value': 'test@example.com'}]
    }

@pytest.fixture()
def task_response_related_person_owner(user_id, patient_id, resource_id):
    return {
        "resourceType": "Task",
        "id": resource_id.split('/')[-1],
        "for": {"reference": patient_id},
        "owner": {"reference": user_id},
        "status": "ready"
    }

@pytest.fixture()
def task_response_end_of_life(user_id, patient_id, resource_id):
    return {
        "resourceType": "Task",
        "id": resource_id.split('/')[-1],
        "for": {"reference": patient_id},
        "owner": {"reference": user_id},
        "status": "cancelled"
    }

@pytest.fixture()
def task_response_careteam_owner(patient_id, resource_id):
    return {
        "resourceType": "Task",
        "id": resource_id.split('/')[-1],
        "for": {"reference": patient_id},
        "owner": {"reference": "CareTeam/careteam-id"},
        "status": "ready"
    }

@pytest.fixture()
def careteam_active_with_member(user_id):
    return {
        "resourceType": "CareTeam",
        "id": "careteam-id",
        "status": "active",
        "participant": [{"member": {"reference": user_id}}]
    }

@pytest.fixture()
def careteam_inactive_with_member(user_id):
    return {
        "resourceType": "CareTeam",
        "id": "careteam-id",
        "status": "inactive",
        "participant": [{"member": {"reference": user_id}}]
    }

@pytest.fixture()
def careteam_active_without_member():
    return {
        "resourceType": "CareTeam",
        "id": "careteam-id",
        "status": "active",
        "participant": [{"member": {"reference": "RelatedPerson/other-id"}}]
    }


def _mock_related_person_launch_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = status_code < 300

        def json(self):
            return self.json_data

    data = {'id_token': jwt.encode({'email': 'test@example.com'}, 'secret')}
    return MockResponse(data, 200)


def _mock_related_person(related_person_response, task_response, careteam_response, *args, **kwargs):
    if 'openid-configuration' in args[0]:
        return MockResponse({'authorization_endpoint': 'http://localhost:5000/idp/authorize', 'token_endpoint': 'http://localhost:5000/idp/token'}, 200)

    if 'RelatedPerson' in args[0]:
        return MockResponse(related_person_response, 200)

    if 'Task' in args[0]:
        if not task_response:
            return MockResponse(task_response, 404)

        return MockResponse(task_response, 200)

    if 'CareTeam' in args[0]:
        if not careteam_response:
            return MockResponse(careteam_response, 404)

        return MockResponse(careteam_response, 200)

    return MockResponse({}, 404, reason="Not Found")


class MockResponse:
    def __init__(self, json_data, status_code, reason=""):
        self.json_data = json_data
        self.status_code = status_code
        self.ok = status_code < 400
        self.reason = reason

    def json(self):
        return self.json_data


@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_launch_happy_path(mock_get, mock_post, active_related_person, task_response_related_person_owner, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(active_related_person, task_response_related_person_owner, None, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
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
            'redirect_uri': allowed_redirect.url,
            'grant_type': 'authorization_code'}

    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 200
    response_data = rv.json
    access_token = response_data.get('access_token')
    assert access_token is not None
    assert response_data['sub'] == user_id
    assert response_data['patient'] == patient_id
    assert response_data['resource'] == resource_id


@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_inactive_not_checked(mock_get, mock_post, inactive_related_person, task_response_related_person_owner, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(inactive_related_person, task_response_related_person_owner, None, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 302


@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_identifier_not_matching(mock_get, mock_post, related_person_with_different_identifier, task_response_related_person_owner, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(related_person_with_different_identifier, task_response_related_person_owner, None, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 403


@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_patient_not_matching(mock_get, mock_post, related_person_with_different_patient, task_response_related_person_owner, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(related_person_with_different_patient, task_response_related_person_owner, None, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 403

@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_task_not_found_not_checked(mock_get, mock_post, active_related_person, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    # Return 404 for task in the mock
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(active_related_person, None, None, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 302

@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_task_not_active_not_checked(mock_get, mock_post, active_related_person, task_response_end_of_life, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):

    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(active_related_person, task_response_end_of_life, None, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 302


@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_active_careteam_member(mock_get, mock_post, active_related_person, task_response_careteam_owner, careteam_active_with_member, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(active_related_person, task_response_careteam_owner, careteam_active_with_member, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
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
            'redirect_uri': allowed_redirect.url,
            'grant_type': 'authorization_code'}

    rv = testing_app.post('/oauth2/token', data=data, headers={'Accept': 'application/javascript'})
    assert rv.status_code == 200
    response_data = rv.json
    access_token = response_data.get('access_token')
    assert access_token is not None
    assert response_data['sub'] == user_id
    assert response_data['patient'] == patient_id
    assert response_data['resource'] == resource_id


@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_inactive_careteam_member_not_checked(mock_get, mock_post, active_related_person, task_response_careteam_owner, careteam_inactive_with_member, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(active_related_person, task_response_careteam_owner, careteam_inactive_with_member, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 302


@mock.patch('requests.post', side_effect=_mock_related_person_launch_post)
@mock.patch('requests.get')
def test_related_person_active_careteam_not_member_not_checked(mock_get, mock_post, active_related_person, task_response_careteam_owner, careteam_active_without_member, testing_app: FlaskClient, client_key: Key, portal_key: Key, client_id: str, portal_id: str, user_id: str, patient_id: str, resource_id: str, smart_service_client: SmartService, smart_service_portal: SmartService, allowed_redirect: AllowedRedirect):
    mock_get.side_effect = lambda *args, **kwargs: _mock_related_person(active_related_person, task_response_careteam_owner, careteam_active_without_member, *args, **kwargs)

    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id, f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 302
