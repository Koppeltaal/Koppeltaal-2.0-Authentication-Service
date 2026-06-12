# Split Authentication AuditEvents (IG Topic 11 §3.6/§3.7) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single combined login AuditEvent with three separate User Authentication AuditEvents (Login `110122`, Authentication Delegated to IdP `110144`, IdP Authentication Decision `110145`) and add a Token Introspection AuditEvent (`110143`) for HTI launch tokens, per IG memo topic 11 §3.6/§3.7.

**Architecture:** `FhirLoggingService` gets a shared event builder plus four public registration methods; `verify_token` returns the token type alongside the claims so the introspect endpoint logs only for HTI launch tokens; `/oauth2/authorize` logs Login + delegation, the IdP callback logs the decision (success and failure). All audit logging is best-effort and never breaks the auth flow.

**Tech Stack:** Python 3.12, Flask, PyJWT, fhir.resources (pydantic v1), pytest with unittest.mock. Tests run in Docker (the local venv is broken).

**Spec:** `docs/superpowers/specs/2026-06-12-auditevent-topic11-design.md`

**Test command** (substitute the test file; running the whole suite drops the path filter):

```bash
docker run --rm -v "$(pwd)":/app -w /app python:3.12 \
  bash -c "pip install -q poetry && poetry install --with test -q && poetry run python -m pytest test/<FILE> -v"
```

**Conventions:** conventional commit format, English, no Co-Authored-By lines.

---

## File structure

- `application/utils.py` — add `get_trace_headers(headers, default_trace_id=None)`: shared extraction of trace headers from incoming request headers (moved from `IdpService._get_trace_headers`, made a pure function).
- `application/fhir_logging_client/service.py` — shared builder (`_base_user_authentication_event`, `_add_person_entity`, `_add_idp_agent`, `_add_person_agent`, `_trace_extensions`, `_person_type`), best-effort `_post_audit_event`, internal dispatcher `_register_user_authentication_event`, and four public methods. `register_idp_interaction` and `_get_audit_event` stay until Task 9, then get deleted.
- `application/oauth_server/verifiers.py` — `verify_token` returns `(token_type, claims)`.
- `application/oauth_server/views.py` — `/oauth2/authorize` logs Login + delegation; `/oauth2/introspect` logs introspection for `hti_launch` tokens.
- `application/idp_client/service.py` — `consume_idp_code` logs the IdP decision (outcome `"0"`/`"4"`), uses the shared trace-header helper.
- Tests: `test/test_utils.py` (new), `test/test_fhir_logging_service.py`, `test/test_introspect.py`, `test/test_oauth_flows.py`.

**Known constraint:** `LAUNCH_SCOPE_ALLOWED` (`application/oauth_server/service.py:24`) only allows `['launch', 'openid', 'fhirUser']`, so the non-openid branch of `/authorize` is currently unreachable. The Login event is logged before the branch split, so it covers both branches without a dedicated non-openid test.

---

### Task 1: Shared trace-header helper

**Files:**
- Modify: `application/utils.py`
- Test: `test/test_utils.py` (new)

- [ ] **Step 1: Write the failing tests**

Create `test/test_utils.py`:

```python
from application.utils import get_trace_headers


def test_get_trace_headers_generates_request_id():
    headers = get_trace_headers({})
    assert headers['X-Request-Id']
    assert 'X-Correlation-Id' not in headers
    assert 'X-Trace-Id' not in headers


def test_get_trace_headers_passes_headers_through():
    incoming = {'X-Request-Id': 'req-1', 'X-Correlation-Id': 'cor-1', 'X-Trace-Id': 'trace-1'}
    assert get_trace_headers(incoming) == incoming


def test_get_trace_headers_uses_default_trace_id():
    headers = get_trace_headers({}, default_trace_id='jti-1')
    assert headers['X-Trace-Id'] == 'jti-1'


def test_get_trace_headers_header_wins_over_default():
    headers = get_trace_headers({'X-Trace-Id': 'from-header'}, default_trace_id='jti-1')
    assert headers['X-Trace-Id'] == 'from-header'
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_utils.py`.
Expected: FAIL — `ImportError: cannot import name 'get_trace_headers'`.

- [ ] **Step 3: Implement the helper**

In `application/utils.py`, add below `new_trace_headers`:

```python
def get_trace_headers(headers, default_trace_id: str = None) -> dict:
    """Extract trace headers from incoming request headers; generates X-Request-Id when absent."""
    trace_headers = {'X-Request-Id': headers.get('X-Request-Id', str(uuid4()))}
    if 'X-Correlation-Id' in headers:
        trace_headers['X-Correlation-Id'] = headers['X-Correlation-Id']
    if 'X-Trace-Id' in headers:
        trace_headers['X-Trace-Id'] = headers['X-Trace-Id']
    elif default_trace_id:
        trace_headers['X-Trace-Id'] = default_trace_id
    return trace_headers
```

(`uuid4` is already imported in `application/utils.py`.)

- [ ] **Step 4: Run the tests to verify they pass**

Run the test command with `test/test_utils.py`.
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add application/utils.py test/test_utils.py
git commit -m "feat(utils): add shared trace-header extraction helper"
```

---

### Task 2: AuditEvent builder + `register_login` (110122)

**Files:**
- Modify: `application/fhir_logging_client/service.py`
- Test: `test/test_fhir_logging_service.py`

Keep `register_idp_interaction` and `_get_audit_event` untouched in this task — `IdpService` still calls them. They are removed in Task 9.

- [ ] **Step 1: Write the failing tests**

Append to `test/test_fhir_logging_service.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_fhir_logging_service.py`.
Expected: the 4 new tests FAIL with `AttributeError: 'FhirLoggingService' object has no attribute 'register_login'`; all existing tests still pass.

- [ ] **Step 3: Implement the builder and `register_login`**

In `application/fhir_logging_client/service.py`, add module-level constants below the logger setup:

```python
DCM_SYSTEM = "http://dicom.nema.org/resources/ontology/DCM"

PERSON_ROLE_CODES = {
    "Patient": {"code": "1", "display": "Patient"},
    "RelatedPerson": {"code": "6", "display": "User"},
    "Practitioner": {"code": "15", "display": "Practitioner"},
}
```

Add to the `FhirLoggingService` class (above `register_idp_interaction`):

```python
    @staticmethod
    def register_login(entity_what_reference: str, requesting_client_id: str, trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110122", "Login",
            requesting_client_id, trace_headers,
            entity_what_reference=entity_what_reference)

    @staticmethod
    def _register_user_authentication_event(subtype_code: str, subtype_display: str,
                                            requesting_client_id: str, trace_headers: dict,
                                            outcome: str = "0",
                                            entity_what_reference: str = None,
                                            idp_name: str = None, idp_issuer: str = None,
                                            agent_who_reference: str = None):
        logger.info(f"Registering User Authentication AuditEvent (subtype [{subtype_code}]) "
                    f"for client [{requesting_client_id}]")
        try:
            data = FhirLoggingService._base_user_authentication_event(
                subtype_code, subtype_display, requesting_client_id, outcome, trace_headers)
            if entity_what_reference is not None:
                FhirLoggingService._add_person_entity(data, entity_what_reference)
            if idp_name or idp_issuer:
                FhirLoggingService._add_idp_agent(data, idp_name, idp_issuer)
            if agent_who_reference is not None:
                FhirLoggingService._add_person_agent(data, agent_who_reference)
            AuditEvent(**data)  # trigger validation
        except Exception:
            logger.exception(f"Failed to build User Authentication AuditEvent (subtype [{subtype_code}])")
            return None
        return FhirLoggingService._post_audit_event(data, trace_headers)

    @staticmethod
    def _base_user_authentication_event(subtype_code: str, subtype_display: str,
                                        requesting_client_id: str, outcome: str,
                                        trace_headers: dict) -> dict:
        return {
            "resourceType": "AuditEvent",
            "meta": {
                "profile": [
                    "http://koppeltaal.nl/fhir/StructureDefinition/KT2AuditEvent"
                ]
            },
            "extension": FhirLoggingService._trace_extensions(trace_headers),
            "type": {
                "system": DCM_SYSTEM,
                "code": "110114",
                "display": "User Authentication"
            },
            "subtype": [{
                "system": DCM_SYSTEM,
                "code": subtype_code,
                "display": subtype_display
            }],
            "action": "E",
            "outcome": outcome,
            "recorded": datetime.now(timezone.utc).isoformat("T", "milliseconds"),
            "agent": [
                {
                    "type": {
                        "coding": [
                            {
                                "system": DCM_SYSTEM,
                                "code": "110153",
                                "display": "Source Role ID"
                            }
                        ]
                    },
                    "who": {
                        "reference": f"Device/{requesting_client_id}",
                        "type": "Device"
                    },
                    "requestor": True
                }
            ],
            "source": {
                "site": current_app.config['AUTH_SERVER_ISS'],
                "observer": {
                    "reference": f"Device/{current_app.config['SMART_BACKEND_SERVICE_DEVICE_ID']}",
                    "type": "Device"
                },
                "type": [{
                    "system": "http://terminology.hl7.org/CodeSystem/security-source-type",
                    "code": "6",
                    "display": "Security Server"
                }]
            }
        }

    @staticmethod
    def _trace_extensions(trace_headers: dict) -> list:
        extension_ = []
        if 'X-Request-Id' in trace_headers:
            extension_.append({
                "url": "http://koppeltaal.nl/fhir/StructureDefinition/request-id",
                "valueId": trace_headers['X-Request-Id']
            })
        if 'X-Correlation-Id' in trace_headers:
            extension_.append({
                "url": "http://koppeltaal.nl/fhir/StructureDefinition/correlation-id",
                "valueId": trace_headers['X-Correlation-Id']
            })
        if 'X-Trace-Id' in trace_headers:
            extension_.append({
                "url": "http://koppeltaal.nl/fhir/StructureDefinition/trace-id",
                "valueId": trace_headers['X-Trace-Id']
            })
        return extension_

    @staticmethod
    def _person_type(reference: str) -> str:
        person_type = (reference or "").split("/")[0]
        if person_type not in PERSON_ROLE_CODES:
            raise ValueError(f"Entity type must be Patient, Practitioner or RelatedPerson. "
                             f"Got [{person_type}] instead.")
        return person_type

    @staticmethod
    def _add_person_entity(data: dict, entity_what_reference: str):
        person_type = FhirLoggingService._person_type(entity_what_reference)
        role = PERSON_ROLE_CODES[person_type]
        data["entity"] = [
            {
                "what": {
                    "reference": entity_what_reference,
                    "type": person_type
                },
                "role": {
                    "system": "http://terminology.hl7.org/CodeSystem/object-role",
                    "code": role["code"],
                    "display": role["display"]
                }
            }
        ]

    @staticmethod
    def _add_idp_agent(data: dict, idp_name: str, idp_issuer: str):
        agent_who = {}
        if idp_name:
            agent_who["display"] = idp_name
        if idp_issuer:
            agent_who["identifier"] = {
                "system": "http://koppeltaal.nl/oidc/issuer",
                "value": idp_issuer
            }
        data["agent"].append({
            "type": {
                "coding": [
                    {
                        "system": DCM_SYSTEM,
                        "code": "110152",
                        "display": "Destination Role ID"
                    }
                ]
            },
            "who": agent_who,
            "requestor": False
        })

    @staticmethod
    def _add_person_agent(data: dict, reference: str):
        person_type = FhirLoggingService._person_type(reference)
        data["agent"].append({
            "who": {
                "reference": reference,
                "type": person_type
            },
            "requestor": False
        })

    @staticmethod
    def _post_audit_event(data: dict, trace_headers: dict):
        try:
            access_token = token_service.get_system_access_token()
            endpoint = f'{current_app.config["FHIR_CLIENT_SERVERURL"]}/AuditEvent'
            logger.info(f"About to submit AuditEvent to endpoint [{endpoint}]")
            logger.info(f"generated audit event json: {data}")
            headers = new_trace_headers(trace_headers,
                                        {"Authorization": f"Bearer {access_token}",
                                         "Content-Type": "application/fhir+json;charset=utf-8"})
            response = requests.post(endpoint, json=data, headers=headers)
        except Exception:
            logger.exception("Failed to submit AuditEvent to the FHIR server")
            return None

        if response.ok:
            logger.info(f"Audit event created successfully with code [{response.status_code}]")
        else:
            logger.warning(f"Failed to create AuditEvent, server responded with code "
                           f"[{response.status_code}] and reason: [{response.reason}]")
        return response
```

- [ ] **Step 4: Run the tests to verify they pass**

Run the test command with `test/test_fhir_logging_service.py`.
Expected: all tests pass (new and pre-existing).

- [ ] **Step 5: Commit**

```bash
git add application/fhir_logging_client/service.py test/test_fhir_logging_service.py
git commit -m "feat(audit): add event builder and register_login (DCM 110122)"
```

---

### Task 3: `register_idp_delegation` (110144)

**Files:**
- Modify: `application/fhir_logging_client/service.py`
- Test: `test/test_fhir_logging_service.py`

- [ ] **Step 1: Write the failing tests**

Append to `test/test_fhir_logging_service.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_fhir_logging_service.py`.
Expected: 2 new tests FAIL with `AttributeError: ... no attribute 'register_idp_delegation'`.

- [ ] **Step 3: Implement**

Add to `FhirLoggingService`, below `register_login`:

```python
    @staticmethod
    def register_idp_delegation(entity_what_reference: str, requesting_client_id: str,
                                idp_name: str, idp_issuer: str, trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110144", "Authentication Delegated to IdP",
            requesting_client_id, trace_headers,
            entity_what_reference=entity_what_reference,
            idp_name=idp_name, idp_issuer=idp_issuer)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run the test command with `test/test_fhir_logging_service.py`. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add application/fhir_logging_client/service.py test/test_fhir_logging_service.py
git commit -m "feat(audit): add register_idp_delegation (DCM 110144)"
```

---

### Task 4: `register_idp_decision` (110145)

**Files:**
- Modify: `application/fhir_logging_client/service.py`
- Test: `test/test_fhir_logging_service.py`

- [ ] **Step 1: Write the failing tests**

Append to `test/test_fhir_logging_service.py`:

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_fhir_logging_service.py`.
Expected: 2 new tests FAIL with `AttributeError: ... no attribute 'register_idp_decision'`.

- [ ] **Step 3: Implement**

Add to `FhirLoggingService`, below `register_idp_delegation`:

```python
    @staticmethod
    def register_idp_decision(entity_what_reference: str, requesting_client_id: str,
                              idp_name: str, idp_issuer: str, outcome: str, trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110145", "IdP Authentication Decision",
            requesting_client_id, trace_headers,
            outcome=outcome,
            entity_what_reference=entity_what_reference,
            idp_name=idp_name, idp_issuer=idp_issuer)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run the test command with `test/test_fhir_logging_service.py`. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add application/fhir_logging_client/service.py test/test_fhir_logging_service.py
git commit -m "feat(audit): add register_idp_decision (DCM 110145)"
```

---

### Task 5: `register_token_introspection` (110143) + best-effort guarantee

**Files:**
- Modify: `application/fhir_logging_client/service.py`
- Test: `test/test_fhir_logging_service.py`

- [ ] **Step 1: Write the failing tests**

Append to `test/test_fhir_logging_service.py` (also add `import requests` at the top of the file):

```python
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_fhir_logging_service.py`.
Expected: the two introspection tests FAIL with `AttributeError: ... no attribute 'register_token_introspection'`; the connection-error test already passes (the try/except in `_post_audit_event` was built in Task 2) — that is fine, it pins the behavior.

- [ ] **Step 3: Implement**

Add to `FhirLoggingService`, below `register_idp_decision`:

```python
    @staticmethod
    def register_token_introspection(agent_who_reference: str, requesting_client_id: str,
                                     trace_headers: dict):
        return FhirLoggingService._register_user_authentication_event(
            "110143", "Token Introspection (HTI launch)",
            requesting_client_id, trace_headers,
            agent_who_reference=agent_who_reference)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run the test command with `test/test_fhir_logging_service.py`. Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add application/fhir_logging_client/service.py test/test_fhir_logging_service.py
git commit -m "feat(audit): add register_token_introspection (DCM 110143)"
```

---

### Task 6: Token type from `verify_token` + introspection logging at `/oauth2/introspect`

**Files:**
- Modify: `application/oauth_server/verifiers.py:22-40`
- Modify: `application/oauth_server/views.py` (`handle_introspect_request`, imports)
- Test: `test/test_introspect.py`

- [ ] **Step 1: Write the failing tests**

In `test/test_introspect.py`, add to the imports at the top:

```python
from unittest import mock

from application.utils import get_private_key_as_pem, get_public_key_as_pem
```

(`get_private_key_as_pem` is already imported; only `mock` is new.)

Append the tests:

```python
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
    assert call_args.args[2]['X-Trace-Id'] == payload['jti']


@mock.patch('application.oauth_server.views.fhir_logging_service')
def test_introspect_access_token_logs_no_audit_event(mock_logging,
                                                     testing_app: FlaskClient,
                                                     server_key: Key,
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
        "iss": 'http://localhost/',
        "jti": str(uuid4()),
        "aud": 'fhir-service'
    }
    json_token = JsonWebToken(algorithms=['RS512'])
    token = json_token.encode(header, payload, get_private_key_as_pem(server_key))
    data = {'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': client_assertion,
            'token': token}
    rv = testing_app.post('/oauth2/introspect', data=data, headers={'Accept': 'application/javascript'})

    assert rv.json['active']
    mock_logging.register_token_introspection.assert_not_called()


@mock.patch('application.oauth_server.views.fhir_logging_service')
def test_introspect_invalid_token_logs_no_audit_event(mock_logging,
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
    mock_logging.register_token_introspection.assert_not_called()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_introspect.py`.
Expected: the first new test FAILS with `AttributeError: <module 'application.oauth_server.views'> does not have the attribute 'fhir_logging_service'` (the import does not exist yet).

- [ ] **Step 3: Change `verify_token` to return the token type**

In `application/oauth_server/verifiers.py`, replace the body of `verify_token`:

```python
def verify_token(encoded_token: str, auth_client_id: str) -> tuple:
    """
    Dispatches the token to the matching verifier and returns (token_type, claims).

    token_type is one of 'access_token', 'client_credentials', 'hti_launch', or None
    when no verifier condition matched. claims is None when verification failed.
    This dispatch is the single source of truth for recognizing an HTI launch token.
    """
    unverified_decoded_jwt = pyjwt.decode(encoded_token, options={"verify_signature": False})
    iss = unverified_decoded_jwt.get('iss', '')
    aud = unverified_decoded_jwt.get('aud', '')

    token_endpoint = _get_token_endpoint()
    is_client_id = _exists_smart_service(iss)
    if iss == request.url_root and aud == 'fhir-service':
        logger.info("verify_token matched to access_token_verifier")
        return 'access_token', access_token_verifier.verify_and_get_token(encoded_token)
    elif is_client_id and aud == token_endpoint:
        logger.info("verify_token matched to client_credentials_verifier")
        return 'client_credentials', client_credentials_verifier.verify_and_get_token(encoded_token, auth_client_id)
    elif is_client_id and aud.startswith('Device/'):
        logger.info("verify_token matched to hti_token_verifier")
        return 'hti_launch', hti_token_verifier.verify_and_get_token(encoded_token, auth_client_id)

    logger.warning(f"Cannot verify token for issuer [{iss}] and aud [{aud}] - it did not match any condition matched to a verifier")
    return None, None
```

- [ ] **Step 4: Log the introspection event in the view**

In `application/oauth_server/views.py`, add to the imports:

```python
from application.fhir_logging_client.service import fhir_logging_service
from application.utils import get_trace_headers
```

In `handle_introspect_request`, replace:

```python
            auth_client_id = auth_token['iss']  # Issuer of the auth token is the client_id of the calling application.
            decoded = verify_token(token, auth_client_id)

            if decoded:
                # TODO: validate fields
                rv = decoded.copy()
                rv['active'] = True
                return jsonify(rv)
            return jsonify({'active': False})
```

with:

```python
            auth_client_id = auth_token['iss']  # Issuer of the auth token is the client_id of the calling application.
            token_type, decoded = verify_token(token, auth_client_id)

            if decoded:
                # TODO: validate fields
                rv = decoded.copy()
                rv['active'] = True
                if token_type == 'hti_launch':
                    # IG memo topic 11 section 3.7: introspection of an HTI launch token is
                    # recorded as a User Authentication AuditEvent; other token types are not.
                    trace_headers = get_trace_headers(request.headers, default_trace_id=decoded.get('jti'))
                    fhir_logging_service.register_token_introspection(decoded.get('sub'), auth_client_id,
                                                                      trace_headers)
                return jsonify(rv)
            return jsonify({'active': False})
```

- [ ] **Step 5: Run the tests to verify they pass**

Run the test command with `test/test_introspect.py`.
Expected: all tests pass, including the pre-existing ones. Note: `test_introspect_client_happy` uses sub `"1234567890"` without mocking the logging service — the person-reference safety net in `register_token_introspection` skips the event before any HTTP call, so it stays green.

- [ ] **Step 6: Commit**

```bash
git add application/oauth_server/verifiers.py application/oauth_server/views.py test/test_introspect.py
git commit -m "feat(introspect): log AuditEvent for HTI launch token introspection"
```

---

### Task 7: Login + delegation events at `/oauth2/authorize`

**Files:**
- Modify: `application/oauth_server/views.py` (`handle_authorize_request`)
- Test: `test/test_oauth_flows.py`

- [ ] **Step 1: Write the failing tests**

Append to `test/test_oauth_flows.py`:

```python
def _test_openid_config_with_issuer(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = True

        def json(self):
            return self.json_data

    data = {'authorization_endpoint': 'https://unit.test/idp',
            'issuer': 'https://unit.test/issuer'}
    return MockResponse(data, 200)


@mock.patch('application.oauth_server.views.fhir_logging_service')
@mock.patch('requests.get', side_effect=_test_openid_config_with_issuer)
def test_authorize_logs_login_and_delegation(mock_get, mock_logging, testing_app: FlaskClient,
                                             client_key: Key,
                                             portal_key: Key,
                                             client_id: str,
                                             portal_id: str,
                                             user_id: str,
                                             patient_id: str,
                                             resource_id: str,
                                             identity_provider: IdentityProvider,
                                             smart_service_client: SmartService,
                                             smart_service_portal: SmartService,
                                             allowed_redirect: AllowedRedirect):
    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id,
                                 f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')

    assert authorize_resp.status_code == 302

    mock_logging.register_login.assert_called_once()
    login_args = mock_logging.register_login.call_args
    assert login_args.args[0] == user_id
    assert login_args.args[1] == client_id
    assert 'X-Trace-Id' in login_args.args[2]

    mock_logging.register_idp_delegation.assert_called_once()
    delegation_args = mock_logging.register_idp_delegation.call_args
    assert delegation_args.args[0] == user_id
    assert delegation_args.args[1] == client_id
    # idp_name comes from IdentityProvider.name (not set in the fixture)
    assert delegation_args.args[3] == 'https://unit.test/issuer'
    # both events share the same trace headers
    assert delegation_args.args[4] == login_args.args[2]


@mock.patch('application.oauth_server.views.fhir_logging_service')
@mock.patch('requests.get', side_effect=_test_openid_config_with_issuer)
def test_authorize_invalid_launch_token_logs_nothing(mock_get, mock_logging, testing_app: FlaskClient,
                                                     client_id: str,
                                                     identity_provider: IdentityProvider,
                                                     smart_service_client: SmartService,
                                                     allowed_redirect: AllowedRedirect):
    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': 'not-a-jwt',
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')

    assert authorize_resp.status_code == 400
    mock_logging.register_login.assert_not_called()
    mock_logging.register_idp_delegation.assert_not_called()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_oauth_flows.py`.
Expected: `test_authorize_logs_login_and_delegation` FAILS on `register_login.assert_called_once()` (no call recorded). The invalid-launch test may already pass — fine, it pins behavior.

- [ ] **Step 3: Implement**

In `application/oauth_server/views.py`, in `handle_authorize_request`, replace:

```python
        launch_token = hti_token_verifier.verify_and_get_token(oauth2_session.launch, oauth2_session.client_id)
        if launch_token:
```

with:

```python
        launch_token = hti_token_verifier.verify_and_get_token(oauth2_session.launch, oauth2_session.client_id)
        if launch_token:
            trace_headers = get_trace_headers(request.headers, default_trace_id=launch_token.get('jti'))
            fhir_logging_service.register_login(launch_token.get('sub'), oauth2_session.client_id,
                                                trace_headers)
```

Then replace the two IdP redirect blocks:

```python
                # Use custom IDP if one was selected
                if selected_idp:
                    oauth2_session.identity_provider = selected_idp.id
                    db.session.commit()

                    parameters['client_id'] = selected_idp.client_id
                    data = requests.get(selected_idp.openid_config_endpoint).json()
                    return redirect(f'{data["authorization_endpoint"]}?{urlencode(parameters)}')

                # No custom IDPs configured - use default Koppeltaal IDP
                return redirect(f'{current_app.config["IDP_AUTHORIZE_ENDPOINT"]}?{urlencode(parameters)}')
```

with:

```python
                # Use custom IDP if one was selected
                if selected_idp:
                    oauth2_session.identity_provider = selected_idp.id
                    db.session.commit()

                    parameters['client_id'] = selected_idp.client_id
                    data = requests.get(selected_idp.openid_config_endpoint).json()
                    fhir_logging_service.register_idp_delegation(launch_token['sub'], oauth2_session.client_id,
                                                                 selected_idp.name, data.get('issuer'),
                                                                 trace_headers)
                    return redirect(f'{data["authorization_endpoint"]}?{urlencode(parameters)}')

                # No custom IDPs configured - use default Koppeltaal IDP
                fhir_logging_service.register_idp_delegation(launch_token['sub'], oauth2_session.client_id,
                                                             'default', None, trace_headers)
                return redirect(f'{current_app.config["IDP_AUTHORIZE_ENDPOINT"]}?{urlencode(parameters)}')
```

(The imports for `fhir_logging_service` and `get_trace_headers` were added in Task 6.)

- [ ] **Step 4: Run the tests to verify they pass**

Run the test command with `test/test_oauth_flows.py`.
Expected: all tests pass. Pre-existing flow tests stay green because they mock `requests.post`/`requests.get` globally, so the real `fhir_logging_service` POSTs hit the mock.

- [ ] **Step 5: Commit**

```bash
git add application/oauth_server/views.py test/test_oauth_flows.py
git commit -m "feat(authorize): log login and IdP delegation AuditEvents"
```

---

### Task 8: IdP decision logging in `consume_idp_code`

**Files:**
- Modify: `application/idp_client/service.py`
- Test: `test/test_oauth_flows.py`

- [ ] **Step 1: Write the failing tests**

Append to `test/test_oauth_flows.py`:

```python
def _test_authorization_code_mismatch_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code
            self.ok = True

        def json(self):
            return self.json_data

    data = {'sub': 'wrong@example.com',
            'email': 'wrong@example.com'}
    id_token = jwt.encode(data, key=None, algorithm='none')
    return MockResponse({'id_token': id_token}, 200)


@mock.patch('application.idp_client.service.fhir_logging_service')
@mock.patch('requests.post', side_effect=_test_authorization_code_happy_post)
@mock.patch('requests.get', side_effect=_test_authorization_code_happy_get)
def test_idp_decision_success_logged(mock_get, mock_post, mock_logging, testing_app: FlaskClient,
                                     client_key: Key,
                                     portal_key: Key,
                                     client_id: str,
                                     portal_id: str,
                                     user_id: str,
                                     patient_id: str,
                                     resource_id: str,
                                     smart_service_client: SmartService,
                                     smart_service_portal: SmartService,
                                     allowed_redirect: AllowedRedirect):
    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id,
                                 f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 302
    mock_logging.register_idp_decision.assert_called_once()
    call_args = mock_logging.register_idp_decision.call_args
    assert call_args.args[0] == user_id
    assert call_args.args[1] == client_id
    assert call_args.args[4] == "0"


@mock.patch('application.idp_client.service.fhir_logging_service')
@mock.patch('requests.post', side_effect=_test_authorization_code_mismatch_post)
@mock.patch('requests.get', side_effect=_test_authorization_code_happy_get)
def test_idp_decision_failure_logged_on_user_mismatch(mock_get, mock_post, mock_logging,
                                                      testing_app: FlaskClient,
                                                      client_key: Key,
                                                      portal_key: Key,
                                                      client_id: str,
                                                      portal_id: str,
                                                      user_id: str,
                                                      patient_id: str,
                                                      resource_id: str,
                                                      smart_service_client: SmartService,
                                                      smart_service_portal: SmartService,
                                                      allowed_redirect: AllowedRedirect):
    state = str(uuid4())
    data = {'scope': 'launch fhirUser openid',
            'redirect_uri': allowed_redirect.url,
            'aud': testing_app.application.config.get('FHIR_CLIENT_SERVERURL'),
            'client_id': client_id,
            'launch': _hti_token(testing_app, portal_key, portal_id, user_id, patient_id, resource_id,
                                 f'Device/{smart_service_client.fhir_store_device_id}'),
            'state': state}
    authorize_resp = testing_app.get(f'/oauth2/authorize?{urlencode(data)}')
    idp_code = str(uuid4())
    idp_state = _get_params_from_redirect(authorize_resp, 'state')
    redirect_resp = testing_app.get(f'/idp/oidc/code?code={idp_code}&state={idp_state}')

    assert redirect_resp.status_code == 403
    mock_logging.register_idp_decision.assert_called_once()
    call_args = mock_logging.register_idp_decision.call_args
    assert call_args.args[0] == user_id
    assert call_args.args[4] == "4"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run the test command with `test/test_oauth_flows.py`.
Expected: both new tests FAIL on `register_idp_decision.assert_called_once()` (the code still calls `register_idp_interaction`).

- [ ] **Step 3: Implement**

In `application/idp_client/service.py`:

1. Replace the import of `new_trace_headers`:

```python
from application.utils import get_trace_headers, new_trace_headers
```

2. Remove the now-unused `from uuid import uuid4` import and delete the whole `_get_trace_headers` method.

3. Rewrite `consume_idp_code` (changes: `idp_issuer` initialized up front, shared trace helper, a `log_decision_failure` closure called before every failure return after the launch context is known, and `register_idp_decision` instead of `register_idp_interaction` on success):

```python
    def consume_idp_code(self) -> Tuple[str, int]:
        user_claim = "email"
        idp_name = "default"
        idp_issuer = None

        state = request.values.get('state')
        trace_headers = get_trace_headers(request.headers)

        if not state:
            logger.error('No state found on the authentication response')
            return 'Bad request, no state found on the authentication response', 400

        oauth2_session: Oauth2Session = Oauth2Session.query.filter_by(id=state).first()
        if not oauth2_session:
            logger.error(f'No session found based on id {state}')
            return 'Bad request, No session found based on id ' + state, 400

        hti_launch_token = pyjwt.decode(oauth2_session.launch, options={"verify_signature": False})
        sub = hti_launch_token["sub"]
        logger.info(f'[{oauth2_session.id}] Consuming idp oidc code for user {sub}')

        if 'X-Trace-Id' not in trace_headers:
            trace_headers['X-Trace-Id'] = hti_launch_token['jti']  # The JTI token is the trace id if not set

        def log_decision_failure():
            # IG memo topic 11 section 3.6: the IdP decision is recorded with the outcome,
            # also when authentication is rejected (outcome 4).
            fhir_logging_service.register_idp_decision(sub, oauth2_session.client_id,
                                                       idp_name, idp_issuer, "4", trace_headers)

        code = request.values.get('code')
        if not code:
            logger.error(f'[{oauth2_session.id}] no code parameter found')
            log_decision_failure()
            return 'Bad request, no code found on the authentication response', 400

        # exchange the IDP code, we need the id_token from the response to verify the authenticated user matches the
        # user from the launch. This way we know the user really is the same person as the HTI token states.
        # When a launch token would be compromised, this logic would still make it useless as the identity needs to be
        # verified at the IDP
        oidc_token = self.exchange_idp_code(code, oauth2_session)
        logger.info(f"Received oidc token: {oidc_token}")
        encoded_id_token = oidc_token['id_token']
        if not encoded_id_token:
            logger.error(f'[{oauth2_session.id}] no id_token found')
            log_decision_failure()
            return 'Bad request, no id_token found', 400

        id_token = pyjwt.decode(encoded_id_token, options={"verify_signature": False})  # TODO: Verify signature

        if oauth2_session.identity_provider:
            identity_provider: IdentityProvider = IdentityProvider.query.filter_by(id=oauth2_session.identity_provider).first()
            user_claim = identity_provider.username_attribute  # overwrite the default claim "email"
            idp_name = identity_provider.name

        user_identifier = id_token.get(user_claim)
        if not user_identifier:
            logger.error(f'[{oauth2_session.id}] no [{user_claim}] claim found in id_token')
            log_decision_failure()
            return f'Bad request, no [{user_claim}] claim found in id_token', 400

        # The `iss` claim is required by the OIDC spec (Section 2), but not enforced here
        # to avoid blocking audit logging when an IdP omits it.
        idp_issuer = id_token.get("iss")
        if idp_issuer:
            logger.info(f'[{oauth2_session.id}] IdP id_token contains claim [iss] with value [{idp_issuer}]')
        else:
            logger.warning(f'[{oauth2_session.id}] no [iss] claim found in id_token, continuing without issuer')

        # get the user from the FHIR server, to verify if the Patient has this email set as an identifier
        access_token = token_service.get_system_access_token()

        headers = new_trace_headers(trace_headers, {"Authorization": "Bearer " + access_token})

        launching_user_response = requests.get(f'{current_app.config["FHIR_CLIENT_SERVERURL"]}/{sub}', headers=headers)
        if not launching_user_response.ok:
            logger.error(f'Failed to fetch user {sub} with error code [{launching_user_response.status_code}] and message: \n{launching_user_response.reason}')
            log_decision_failure()
            return 'Bad request, user could not be fetched from store', 400

        launching_user_resource = launching_user_response.json()
        logger.debug(f'[{oauth2_session.id}] Found user resource from the fhir server with reference [{sub}]\n\nuser: {str(launching_user_resource)}')

        if launching_user_resource['resourceType'] == "RelatedPerson":
            headers = new_trace_headers(headers, {"Authorization": "Bearer " + access_token})
            error = self.handle_relatedperson_checks(launching_user_resource, hti_launch_token, headers, access_token)
            if error:
                log_decision_failure()
                return error

        identifiers = launching_user_resource['identifier']
        values = [identifier['value'] for identifier in identifiers if 'value' in identifier]
        if user_identifier not in values:
            logger.error(f'[{oauth2_session.id}] user id mismatch, expected [{user_identifier}] but found {str(values)}')
            log_decision_failure()
            return f'Forbidden, patient identifier [{user_identifier}] not found on [{sub}]', 403

        logger.info(f'[{oauth2_session.id}] user id matched between HTI and IDP by user_identifier [{user_identifier}]')

        fhir_logging_service.register_idp_decision(sub, oauth2_session.client_id,
                                                   idp_name, idp_issuer, "0", trace_headers)

        # As the user has been verified, finish the initial OAuth launch flow by responding with the code
        return f'{oauth2_session.redirect_uri}?{urlencode({"code": oauth2_session.code, "state": oauth2_session.state})}', 302
```

(Note: `user_identifier = id_token.get(user_claim)` replaces `id_token[user_claim]` so a missing claim reaches the logged failure branch instead of raising `KeyError`.)

- [ ] **Step 4: Run the tests to verify they pass**

Run the test command with `test/test_oauth_flows.py`.
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add application/idp_client/service.py test/test_oauth_flows.py
git commit -m "feat(idp): log IdP decision AuditEvent with outcome on success and failure"
```

---

### Task 9: Remove `register_idp_interaction` and its tests

**Files:**
- Modify: `application/fhir_logging_client/service.py`
- Modify: `test/test_fhir_logging_service.py`

- [ ] **Step 1: Verify nothing references the old method**

Run: `rg -n "register_idp_interaction" application/`
Expected: only the definition in `application/fhir_logging_client/service.py` (the `idp_client` call site was replaced in Task 8).

- [ ] **Step 2: Delete the old code**

In `application/fhir_logging_client/service.py`, delete the `register_idp_interaction` and `_get_audit_event` methods.

In `test/test_fhir_logging_service.py`, delete the old tests that exercise `register_idp_interaction`:
`test_happy`, `test_happy_headers`, `test_happy_related_person`, `test_idp_agent_present`,
`test_idp_agent_without_identity_provider`, `test_idp_agent_empty_identity_provider`,
`test_idp_agent_with_practitioner`, `test_idp_agent_has_issuer_identifier`,
`test_idp_agent_issuer_only`, `test_idp_agent_name_only`, `test_invalid_entity_type`.
Their coverage moved to the `register_login`/`register_idp_delegation`/`register_idp_decision` tests in Tasks 2-4. Also remove the now-unused `import pytest` if nothing else in the file uses it.

- [ ] **Step 3: Run the full test suite**

Run the test command with `test/` (the whole suite).
Expected: all tests pass. If a pre-existing test fails because it hits the real network through the new audit logging (unmocked `requests.post` on an `/authorize` or `/idp/oidc/code` call), patch that test with `@mock.patch('requests.post', side_effect=_test_fhir_logging_happy_post)` or mock the logging service object, following the patterns above.

- [ ] **Step 4: Commit**

```bash
git add application/fhir_logging_client/service.py test/test_fhir_logging_service.py
git commit -m "refactor(audit): remove combined register_idp_interaction event"
```

---

### Task 10: Changelog

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add the entry**

Under `## [Unreleased]` / `### Added`, append:

```markdown
- Split login AuditEvents per IG memo topic 11 §3.6: Login (DCM#110122) at `/oauth2/authorize`, Authentication Delegated to IdP (DCM#110144) before the IdP redirect, and IdP Authentication Decision (DCM#110145) at the IdP callback with outcome `0`/`4`
- Token Introspection AuditEvent (DCM#110143) at `/oauth2/introspect`, only for HTI launch tokens, with the launch person on `agent.who` (IG memo topic 11 §3.7)
```

Under `### Changed`, append:

```markdown
- `verify_token` now returns `(token_type, claims)` so the introspect endpoint can distinguish HTI launch tokens from access/client-credentials tokens
- Audit logging is best-effort: FHIR server connection errors no longer break the authentication flow
- Removed the combined `register_idp_interaction` AuditEvent in favor of the three split events
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: update changelog for topic-11 AuditEvent split"
```
