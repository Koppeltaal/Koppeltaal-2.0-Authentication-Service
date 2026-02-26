# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- IdP issuer (`iss` claim) as `agent.who.identifier` on AuditEvent, using system `http://koppeltaal.nl/oidc/issuer`
- IdP name as `agent.who.display` (Destination Role ID) on AuditEvent
- Tests for IdP agent presence, absence, issuer-only, name-only, and Practitioner entity combinations

### Changed
- Bumped Python from 3.9 to 3.12 (pyproject.toml + Dockerfile)
- Updated Flask from 2.3.3 to 3.1.3 (fixes CVE-2026-27205)
- Updated Werkzeug from 3.1.5 to 3.1.6 (fixes CVE-2026-27199)
- Updated SQLAlchemy from 2.0.46 to 2.0.47
- Updated requests-cache from 1.2.1 to 1.3.0
- Updated pytest from 7.2.2 to 9.0.2
- Updated pytest-mock from 3.10.0 to 3.15.1
- Missing `iss` claim in id_token now logs a warning instead of returning 400, to avoid blocking audit logging

### Fixed
- Swapped argument order (`identity_provider_name` / `trace_headers`) in `IdpService.consume_idp_code` call to `register_idp_interaction`
- Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)`
