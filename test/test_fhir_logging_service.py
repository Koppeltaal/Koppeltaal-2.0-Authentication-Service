from unittest import mock
from uuid import uuid4

import pytest
from authlib.jose import JsonWebKey, Key
from fhir.resources.auditevent import AuditEvent
from flask.testing import FlaskClient

from application import create_app
from application.fhir_logging_client.service import fhir_logging_service
from application.utils import get_private_key_as_pem


def _test_fhir_logging_happy_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = True

        def json(self):
            return self.json_data

    data = kwargs
    return MockResponse(data, 200)


@pytest.fixture()
def server_key() -> Key:
    key: Key = JsonWebKey.generate_key('RSA', 2048, is_private=True)
    key.check_key_op('sign')
    yield key


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
                      'OIDC_SMART_CONFIG_SIGNING_ALGS': ["RS384", "ES384", "RS512"],
                      'OIDC_JWT_PUBLIC_KEY': server_key.as_pem(),
                      'OIDC_JWT_PRIVATE_KEY': private_key_bytes,
                      'SMART_BACKEND_SERVICE_DEVICE_ID': "my-unit-test-auth-server-device-id"
                      })

    with app.test_client() as client:
        with app.app_context():
            yield client


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_happy(mock1, testing_app: FlaskClient):

    testing_app.get("test")  # TODO: Ugly fix to initialize app context - mocking the flask.request would be nicer
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert resp_audit_event.entity[0].what.reference == "Patient/123"
    assert resp_audit_event.agent[0].who.reference == "Device/456"
    assert resp_audit_event.source.observer.reference == "Device/my-unit-test-auth-server-device-id"
    assert resp_audit_event.outcome == "0"
    assert 'Authorization' in resp.json()['headers']
    assert 'X-Request-Id' in resp.json()['headers']

@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_happy_headers(mock1, testing_app: FlaskClient):

    testing_app.get("test")  # TODO: Ugly fix to initialize app context - mocking the flask.request would be nicer
    trace_headers = {
        'X-Request-Id': str(uuid4()),
        'X-Correlation-Id': str(uuid4()),
        'X-Trace-Id': str(uuid4())
    }
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", trace_headers)

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert resp_audit_event.entity[0].what.reference == "Patient/123"
    assert resp_audit_event.agent[0].who.reference == "Device/456"
    assert resp_audit_event.source.observer.reference == "Device/my-unit-test-auth-server-device-id"
    assert resp_audit_event.extension[0].valueId == trace_headers['X-Request-Id']
    assert resp_audit_event.extension[1].valueId == trace_headers['X-Correlation-Id']
    assert resp_audit_event.extension[2].valueId == trace_headers['X-Trace-Id']
    assert resp_audit_event.outcome == "0"
    assert 'Authorization' in resp.json()['headers']
    assert 'X-Request-Id' in resp.json()['headers']
    # Correlation ID should be the original Request ID
    assert trace_headers['X-Request-Id'] == resp.json()['headers']['X-Correlation-Id']
    # Trace ID should remain the same
    assert trace_headers['X-Trace-Id'] == resp.json()['headers']['X-Trace-Id']
