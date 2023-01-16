import base64
from hashlib import sha256
from uuid import uuid4

import pytest

from application.oauth_server.service import TokenAuthorizationCodeService


@pytest.fixture()
def token_authorization_code_service() -> TokenAuthorizationCodeService:
    yield TokenAuthorizationCodeService()

def test_code_challenge(token_authorization_code_service):
    code = str(uuid4())
    code_challenge:str = base64.b64encode(sha256(code.encode('ascii')).digest()).decode('ascii')
    assert token_authorization_code_service.check_challenge(code_challenge, code, 'S256')
def test_code_challenge_stripped(token_authorization_code_service):
    code = str(uuid4())

    while len(code) > 10:
        code_challenge:str = base64.b64encode(sha256(code.encode('ascii')).digest()).decode('ascii')
        while code_challenge.endswith('='):
            code_challenge = code_challenge[:-1]

        assert token_authorization_code_service.check_challenge(code_challenge, code, 'S256')
        code = code[:-1]
