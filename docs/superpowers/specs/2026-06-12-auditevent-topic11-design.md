# Design: Split authentication AuditEvents per IG memo topic 11 (§3.6/§3.7)

Date: 2026-06-12
Source: https://vzvznl.github.io/Koppeltaal-2.0-FHIR/memo-wijzigingen-topic11.html (§3.6, §3.7)

## Goal

Implement the NEN 7513-aligned authentication logging changes from IG memo
TOPKT011:

- **§3.6** — The login moment is no longer recorded as a single AuditEvent but
  as **three separate AuditEvents** around the Koppeltaal launch, all of type
  `DCM#110114` "User Authentication", created by the authorization service.
- **§3.7** — A new AuditEvent is recorded at `/oauth2/introspect`, **only**
  when the introspected token is an HTI launch token. Introspection of access
  or id tokens is technical validation and produces no event.

The subtype codes `DCM#110143`, `DCM#110144`, and `DCM#110145` are provisional
Koppeltaal proposals within the DCM system (reference-implementation first);
they may move to a Koppeltaal-specific CodeSystem after ratification.

## Current state

`FhirLoggingService.register_idp_interaction`
(`application/fhir_logging_client/service.py`) builds one combined event
(subtype `110122` "Login") containing the requesting application agent, the
IdP agent, and the authenticated person as entity. It is called once, from
`IdpService.consume_idp_code` (`application/idp_client/service.py:111`), only
on successful verification. `/oauth2/authorize` and `/oauth2/introspect`
(`application/oauth_server/views.py`) log nothing.

## Decisions made during design

1. **Failures are logged too**: the IdP decision event (`110145`) carries
   `outcome: "0"` on success and `outcome: "4"` (minor failure) on rejected or
   failed authentication. NEN 7513 requires a complete access log.
2. **Introspection event is always logged for HTI launch tokens**, with the
   launch `sub` (Patient/RelatedPerson/Practitioner) on `agent.who`. For
   Practitioner launches the event simply does not count as patient
   engagement downstream.
3. **`entity.what` (the launch person) is present on all three login events**,
   matching the existing `auditevent-launch-example` in the IG.
4. **The `110145` decision event keeps the application and IdP agents** in
   addition to the entity, so the event is self-contained (FHIR requires at
   least one agent).
5. **The `110143` introspection event carries the introspecting application**
   (`Device/<client_id>`, Source Role ID, `requestor=true`) alongside the
   person on `agent.who` (`requestor=false`), so the caller is recorded.

## Service API

`application/fhir_logging_client/service.py` is refactored into one shared
private event builder plus one shared POST helper, with four public methods.
`register_idp_interaction` is removed.

Shared base (all four events): profile `KT2AuditEvent`, type `DCM#110114`
"User Authentication", `action: "E"`, trace extensions
(request-id/correlation-id/trace-id), `recorded` = now (UTC, ms), `source` =
auth server (`site` = `AUTH_SERVER_ISS`, `observer` =
`Device/<SMART_BACKEND_SERVICE_DEVICE_ID>`, type "Security Server").

| Method | Subtype (DCM) | Agents | Entity | Outcome |
|---|---|---|---|---|
| `register_login(entity_ref, client_id, trace_headers)` | `110122` "Login" | requesting app: `Device/<client_id>`, type `110153` Source Role ID, `requestor=true` | person (role 1/6/15) | `"0"` |
| `register_idp_delegation(entity_ref, client_id, idp_name, idp_issuer, trace_headers)` | `110144` "Authentication Delegated to IdP" | app agent + IdP agent: `who.identifier` (system `http://koppeltaal.nl/oidc/issuer`) and/or `who.display`, type `110152` Destination Role ID, `requestor=false` | person | `"0"` |
| `register_idp_decision(entity_ref, client_id, idp_name, idp_issuer, outcome, trace_headers)` | `110145` "IdP Authentication Decision" | app agent + IdP agent | person | `"0"` or `"4"` |
| `register_token_introspection(agent_who_ref, client_id, trace_headers)` | `110143` "Token Introspection (HTI launch)" | introspecting app agent (`110153`, `requestor=true`) + person on `agent.who` (`requestor=false`) | none | `"0"` |

Subtype displays verbatim from the memo: "Login", "Authentication Delegated
to IdP", "IdP Authentication Decision", "Token Introspection (HTI launch)".
All subtype codes use system `http://dicom.nema.org/resources/ontology/DCM`.

Entity role mapping stays as today: Patient → 1 "Patient", RelatedPerson → 6
"User", Practitioner → 15 "Practitioner".

## Call sites and data flow

**`/oauth2/authorize`** (`application/oauth_server/views.py`,
`handle_authorize_request`):

- After the launch token verifies → `register_login(sub, client_id,
  trace_headers)`. Logged in both branches (openid flow and the direct
  redirect-back without openid scope). No event on an invalid launch token
  (no trusted identity).
- Immediately before the redirect to the IdP → `register_idp_delegation(...)`.
  Custom IdP: `display` = logical name, `iss` from the already-fetched openid
  configuration (`data["issuer"]`). Default Koppeltaal IdP: `display` =
  "default", no issuer (the memo allows identifier-with-iss *or*
  display-with-logical-name).

**`consume_idp_code`** (`application/idp_client/service.py`):

- Success path: `register_idp_decision(..., outcome="0", ...)` (replaces
  `register_idp_interaction`).
- Failure paths where the launch person is known (missing `code` parameter,
  missing/invalid `id_token`, missing user claim, user fetch failure,
  RelatedPerson patient mismatch, identifier mismatch) →
  `register_idp_decision(..., outcome="4", ...)` before returning the error.
  The earliest checks (missing `state`, unknown session) have no launch
  context, so no event is possible there.

**`/oauth2/introspect`** (`application/oauth_server/views.py`,
`handle_introspect_request`):

- `verify_token` (`application/oauth_server/verifiers.py`) is changed to
  return the token type alongside the claims (`('hti_launch' |
  'access_token' | 'client_credentials', claims)`), since its dispatch
  already determines which verifier matched. It has a single caller (the
  introspect view), so the contract change is cheap.
- The view calls `register_token_introspection(decoded['sub'],
  auth_client_id, trace_headers)` **only** when the matched type is
  `hti_launch`, before returning the introspection response. The token-type
  decision is not re-derived in the view (no duplicated
  `aud.startswith('Device/')` check): the verifier dispatch is the single
  source of truth, so if the Koppeltaal launch-token `aud` convention ever
  changes, the audit logging follows automatically. (The HTI spec itself only
  requires `aud` to be "a reference to the module provider" agreed between
  parties; `Device/<fhir_store_device_id>` is the current Koppeltaal
  convention enforced by `HtiTokenVerifier`.)
- As a safety net, `register_token_introspection` verifies that `sub` is a
  person reference (Patient/RelatedPerson/Practitioner) before putting it on
  `agent.who`; otherwise it logs an error and skips the event.
- Failed introspection (`active: false`) logs nothing. Access tokens and
  client-credentials tokens log nothing (§3.7).

**Trace headers**: the `IdpService._get_trace_headers` logic moves to
`application/utils.py` as a shared helper. `X-Trace-Id` falls back to the
launch token `jti`, as `consume_idp_code` does today, so all three login
events plus the introspection event are linkable by trace id.

## Error handling

- Audit logging is best-effort: `requests.RequestException` during the
  AuditEvent POST and validation errors in the event builder log a
  warning/error but never break the auth flow. (New — today a connection
  error would propagate.)
- An HTTP error response from the FHIR server keeps current behavior: log a
  warning, continue.
- The entity-type check (Patient/Practitioner/RelatedPerson only) stays in
  the builder; an unexpected type logs an error and skips the event instead
  of producing a 500 deeper in the flow.

## Testing

All tests run via Docker (see CLAUDE.md).

- `test/test_fhir_logging_service.py`: per method, validate the generated
  JSON — subtype code/display, agents (app/IdP/person), entity, outcome,
  trace extensions, and FHIR validation via `AuditEvent(**data)`. Existing
  `register_idp_interaction` tests are converted to the new methods.
- `test/test_oauth_flows.py`: `/authorize` produces the Login and delegation
  events (mocked) with a shared trace id; no delegation event in the
  non-openid branch.
- IdP callback tests: decision event with outcome `"0"` on success, `"4"` on
  identifier mismatch and RelatedPerson mismatch.
- `test/test_introspect.py`: introspection event for a valid HTI launch
  token; no event for access/client-credentials tokens or invalid tokens;
  `verify_token` returns the correct token type per dispatch branch.
- Regression: a FHIR server outage (POST raises) does not break `/authorize`
  or the IdP callback.

## Out of scope

- §3.8 (application-side authentication events) — created by applications
  themselves, not by this service.
- §3.9 (purge lifecycle AuditEvents).
- Retention/engagement derivation (`opschoning-patient-data.html`) — consumes
  these events but lives elsewhere.
