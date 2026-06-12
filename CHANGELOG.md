# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- IdP issuer (`iss` claim) as `agent.who.identifier` on AuditEvent, using system `http://koppeltaal.nl/oidc/issuer`
- IdP name as `agent.who.display` (Destination Role ID) on AuditEvent
- Tests for IdP agent presence, absence, issuer-only, name-only, and Practitioner entity combinations
- Split login AuditEvents per IG memo topic 11 §3.6: Login (DCM#110122) at `/oauth2/authorize`, Authentication Delegated to IdP (DCM#110144) before the IdP redirect, and IdP Authentication Decision (DCM#110145) at the IdP callback with outcome `0`/`4`
- Token Introspection AuditEvent (DCM#110143) at `/oauth2/introspect`, only for HTI launch tokens, with the launch person on `agent.who` (IG memo topic 11 §3.7)

### Changed
- Bumped Python from 3.9 to 3.12 (pyproject.toml + Dockerfile)
- Updated Flask from 2.3.3 to 3.1.3 (fixes CVE-2026-27205)
- Updated Werkzeug from 3.1.5 to 3.1.6 (fixes CVE-2026-27199)
- Updated SQLAlchemy from 2.0.46 to 2.0.47
- Updated requests-cache from 1.2.1 to 1.3.0
- Updated pytest from 7.2.2 to 9.0.2
- Updated pytest-mock from 3.10.0 to 3.15.1
- Missing `iss` claim in id_token now logs a warning instead of returning 400, to avoid blocking audit logging
- `verify_token` now returns `(token_type, claims)` so the introspect endpoint can distinguish HTI launch tokens from access/client-credentials tokens
- Audit logging is best-effort: FHIR server connection errors no longer break the authentication flow
- Removed the combined `register_idp_interaction` AuditEvent in favor of the three split events

### Fixed
- Swapped argument order (`identity_provider_name` / `trace_headers`) in `IdpService.consume_idp_code` call to `register_idp_interaction`
- Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`
