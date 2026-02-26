# CLAUDE.md

## Project overview

Koppeltaal 2.0 Authentication Service — a Flask-based OAuth2/OIDC authentication server for the Koppeltaal 2.0 ecosystem. It handles HTI (Health Tools Interoperability) launches, IdP interactions, SMART on FHIR backend services, and FHIR AuditEvent logging.

## Tech stack

- **Python 3.12** with **Flask** and **Poetry** for dependency management
- **SQLAlchemy** (via Flask-SQLAlchemy) for database models
- **Authlib** for OAuth2/OIDC
- **PyJWT** for JWT handling
- **fhir.resources** (pydantic v1) for FHIR resource validation
- **Docker** (python:3.12 base image) for builds and test execution

## Project structure

- `application/` — main application code
  - `oauth_server/` — OAuth2 server (authorize, token, introspect)
  - `oidc_server/` — OpenID Connect endpoints (JWKS, well-known config)
  - `idp_client/` — Identity Provider interaction (OIDC code flow)
  - `fhir_logging_client/` — FHIR AuditEvent logging service
  - `jwks/` — JWKS client for key fetching
  - `irma_client/` — IRMA authentication client
- `test/` — pytest test suite
- `entrypoint.py` — application entry point

## Running tests

Always use Docker to run tests (the local venv is broken):

```shell
docker run --rm -v "$(pwd)":/app -w /app python:3.12 \
  bash -c "pip install -q poetry && poetry install --with test -q && poetry run python -m pytest test/ -v"
```

## Development commands

```shell
# Build Docker image
docker build . -t koppeltaal-2.0-authentication-service

# Install dependencies
poetry install

# Run the app
poetry run python3 entrypoint.py
```

## Conventions

- Pin exact dependency versions in `pyproject.toml` (no `^` or `~` ranges)
- Tests use `unittest.mock` for mocking HTTP calls (requests.post/get)
- FHIR resources are validated by constructing `AuditEvent(**data)` before returning
- Commit messages: short summary line, optional body explaining "why"
