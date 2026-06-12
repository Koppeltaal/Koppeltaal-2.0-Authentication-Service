from unittest import mock
from uuid import uuid4

import pytest
import requests
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
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", "MyIdP", "https://example.com/idp", {})

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
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", "MyIdP", "https://example.com/idp", trace_headers)

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


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_happy_related_person(mock1, testing_app: FlaskClient):
    """Test logging with a RelatedPerson entity"""
    
    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("RelatedPerson/123", "456", "MyIdP", "https://example.com/idp", {})
    
    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)
    
    assert resp_audit_event.entity[0].what.reference == "RelatedPerson/123"
    assert resp_audit_event.entity[0].role.code == "6"  # Ensure role code is '6' for RelatedPerson
    assert resp_audit_event.entity[0].role.display == "User"  # Ensure role display is 'User'
    assert resp_audit_event.agent[0].who.reference == "Device/456"
    assert resp_audit_event.source.observer.reference == "Device/my-unit-test-auth-server-device-id"
    assert resp_audit_event.outcome == "0"
    assert 'Authorization' in resp.json()['headers']
    assert 'X-Request-Id' in resp.json()['headers']


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_idp_agent_present(mock1, testing_app: FlaskClient):
    """Test that the identity provider agent is added to the audit event"""

    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", "MyIdP", "https://example.com/idp", {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert len(resp_audit_event.agent) == 2
    idp_agent = resp_audit_event.agent[1]
    assert idp_agent.who.display == "MyIdP"
    assert idp_agent.requestor is False
    assert idp_agent.type.coding[0].system == "http://dicom.nema.org/resources/ontology/DCM"
    assert idp_agent.type.coding[0].code == "110152"
    assert idp_agent.type.coding[0].display == "Destination Role ID"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_idp_agent_without_identity_provider(mock1, testing_app: FlaskClient):
    """Test that no identity provider agent is added when both idp_name and idp_issuer are None"""

    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", None, None, {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert len(resp_audit_event.agent) == 1
    assert resp_audit_event.agent[0].who.reference == "Device/456"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_idp_agent_empty_identity_provider(mock1, testing_app: FlaskClient):
    """Test that no identity provider agent is added when both idp_name and idp_issuer are empty"""

    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", "", "", {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert len(resp_audit_event.agent) == 1
    assert resp_audit_event.agent[0].who.reference == "Device/456"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_idp_agent_with_practitioner(mock1, testing_app: FlaskClient):
    """Test that the identity provider agent is added alongside a Practitioner entity"""

    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("Practitioner/789", "456", "HospitalIdP", "https://example.com/idp", {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert resp_audit_event.entity[0].what.reference == "Practitioner/789"
    assert len(resp_audit_event.agent) == 2
    # First agent is the requesting device
    assert resp_audit_event.agent[0].who.reference == "Device/456"
    assert resp_audit_event.agent[0].requestor is True
    # Second agent is the identity provider
    assert resp_audit_event.agent[1].who.display == "HospitalIdP"
    assert resp_audit_event.agent[1].requestor is False


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_idp_agent_has_issuer_identifier(mock1, testing_app: FlaskClient):
    """Test that the IdP agent who contains the issuer identifier"""

    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", "MyIdP", "https://example.com/idp", {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert len(resp_audit_event.agent) == 2
    idp_agent = resp_audit_event.agent[1]
    assert idp_agent.who.display == "MyIdP"
    assert idp_agent.who.identifier.system == "http://koppeltaal.nl/oidc/issuer"
    assert idp_agent.who.identifier.value == "https://example.com/idp"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_idp_agent_issuer_only(mock1, testing_app: FlaskClient):
    """Test that the IdP agent is added with only an issuer (no name)"""

    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", None, "https://example.com/idp", {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert len(resp_audit_event.agent) == 2
    idp_agent = resp_audit_event.agent[1]
    assert idp_agent.who.display is None
    assert idp_agent.who.identifier.system == "http://koppeltaal.nl/oidc/issuer"
    assert idp_agent.who.identifier.value == "https://example.com/idp"
    assert idp_agent.requestor is False


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_idp_agent_name_only(mock1, testing_app: FlaskClient):
    """Test that the IdP agent is added with only a name (no issuer)"""

    testing_app.get("test")
    resp = fhir_logging_service.register_idp_interaction("Patient/123", "456", "MyIdP", None, {})

    json_content = resp.json()['json']
    resp_audit_event = AuditEvent(**json_content)

    assert len(resp_audit_event.agent) == 2
    idp_agent = resp_audit_event.agent[1]
    assert idp_agent.who.display == "MyIdP"
    assert idp_agent.who.identifier is None
    assert idp_agent.requestor is False


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_invalid_entity_type(mock1, testing_app: FlaskClient):
    """Test logging with an invalid entity type, should raise an Exception"""

    with pytest.raises(Exception, match=r"Cannot log IDP interaction - Entity type must be Patient, Practitioner or RelatedPerson. Got \[InvalidType\] instead."):
        fhir_logging_service.register_idp_interaction("InvalidType/123", "456", "MyIdP", "https://example.com/idp", {})


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_login_happy(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    resp = fhir_logging_service.register_login("Patient/123", "456", {})

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.type.code == "110114"
    assert audit_event.subtype[0].code == "110122"
    assert audit_event.subtype[0].display == "Login"
    assert audit_event.subtype[0].system == "http://dicom.nema.org/resources/ontology/DCM"
    assert len(audit_event.agent) == 1
    assert audit_event.agent[0].who.reference == "Device/456"
    assert audit_event.agent[0].requestor is True
    assert audit_event.agent[0].type.coding[0].code == "110153"
    assert audit_event.entity[0].what.reference == "Patient/123"
    assert audit_event.entity[0].role.code == "1"
    assert audit_event.outcome == "0"
    assert audit_event.source.observer.reference == "Device/my-unit-test-auth-server-device-id"
    assert 'Authorization' in resp.json()['headers']


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_login_related_person_role(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    resp = fhir_logging_service.register_login("RelatedPerson/123", "456", {})

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.entity[0].role.code == "6"
    assert audit_event.entity[0].role.display == "User"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_login_trace_headers(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    trace_headers = {
        'X-Request-Id': str(uuid4()),
        'X-Correlation-Id': str(uuid4()),
        'X-Trace-Id': str(uuid4())
    }
    resp = fhir_logging_service.register_login("Patient/123", "456", trace_headers)

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.extension[0].valueId == trace_headers['X-Request-Id']
    assert audit_event.extension[1].valueId == trace_headers['X-Correlation-Id']
    assert audit_event.extension[2].valueId == trace_headers['X-Trace-Id']
    # the original X-Request-Id moves to X-Correlation-Id on the outgoing call
    assert resp.json()['headers']['X-Correlation-Id'] == trace_headers['X-Request-Id']
    assert resp.json()['headers']['X-Trace-Id'] == trace_headers['X-Trace-Id']


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_login_invalid_entity_type_skips_event(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    result = fhir_logging_service.register_login("InvalidType/123", "456", {})

    assert result is None
    mock1.assert_not_called()


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_idp_delegation_happy(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    resp = fhir_logging_service.register_idp_delegation(
        "Patient/123", "456", "MyIdP", "https://example.com/idp", {})

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.subtype[0].code == "110144"
    assert audit_event.subtype[0].display == "Authentication Delegated to IdP"
    assert len(audit_event.agent) == 2
    assert audit_event.agent[0].who.reference == "Device/456"
    idp_agent = audit_event.agent[1]
    assert idp_agent.who.display == "MyIdP"
    assert idp_agent.who.identifier.system == "http://koppeltaal.nl/oidc/issuer"
    assert idp_agent.who.identifier.value == "https://example.com/idp"
    assert idp_agent.requestor is False
    assert idp_agent.type.coding[0].code == "110152"
    assert audit_event.entity[0].what.reference == "Patient/123"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_idp_delegation_name_only(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    resp = fhir_logging_service.register_idp_delegation("Patient/123", "456", "default", None, {})

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.subtype[0].code == "110144"
    assert len(audit_event.agent) == 2
    assert audit_event.agent[1].who.display == "default"
    assert audit_event.agent[1].who.identifier is None


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_idp_decision_success(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    resp = fhir_logging_service.register_idp_decision(
        "Patient/123", "456", "MyIdP", "https://example.com/idp", "0", {})

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.subtype[0].code == "110145"
    assert audit_event.subtype[0].display == "IdP Authentication Decision"
    assert audit_event.outcome == "0"
    assert audit_event.entity[0].what.reference == "Patient/123"
    assert len(audit_event.agent) == 2
    assert audit_event.agent[1].who.display == "MyIdP"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_idp_decision_failure_outcome(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    resp = fhir_logging_service.register_idp_decision(
        "Patient/123", "456", "MyIdP", None, "4", {})

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.subtype[0].code == "110145"
    assert audit_event.outcome == "4"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_token_introspection_happy(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    resp = fhir_logging_service.register_token_introspection("Patient/123", "456", {})

    audit_event = AuditEvent(**resp.json()['json'])

    assert audit_event.subtype[0].code == "110143"
    assert audit_event.subtype[0].display == "Token Introspection (HTI launch)"
    assert len(audit_event.agent) == 2
    # introspecting application
    assert audit_event.agent[0].who.reference == "Device/456"
    assert audit_event.agent[0].requestor is True
    # the launch person on agent.who, per IG memo topic 11 section 3.7
    assert audit_event.agent[1].who.reference == "Patient/123"
    assert audit_event.agent[1].requestor is False
    assert audit_event.entity is None
    assert audit_event.outcome == "0"


@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)
def test_register_token_introspection_non_person_sub_skips_event(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    result = fhir_logging_service.register_token_introspection("1234567890", "456", {})

    assert result is None
    mock1.assert_not_called()


@mock.patch('requests.post', side_effect=requests.exceptions.ConnectionError("fhir server down"))
def test_audit_post_failure_does_not_raise(mock1, testing_app: FlaskClient):
    testing_app.get("test")
    result = fhir_logging_service.register_login("Patient/123", "456", {})

    assert result is None
