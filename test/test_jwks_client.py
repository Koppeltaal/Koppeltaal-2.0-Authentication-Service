import pytest
from jwt import PyJWKClientError
from requests_cache import CachedResponse

from application.oauth_server.jwks_client import CacheHeaderPyJWKClient


def test_fetch_data_200(mocker):
    class ResponseObj:
        def __enter__(self):
            return CachedResponse(content='{"ok": true}'.encode('utf8'), status_code=200)

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    mocker.patch('requests_cache.CachedSession.get', return_value=ResponseObj())
    client = CacheHeaderPyJWKClient("http://nonexist.com/.well-known/jwks.json")
    data = client.fetch_data()
    assert data["ok"]


def test_fetch_data_error1(mocker):
    class ResponseObj:
        def __enter__(self):
            return CachedResponse(content='{"ok": true}'.encode('utf8'), status_code=400)

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    mocker.patch('requests_cache.CachedSession.get', return_value=ResponseObj())

    client = CacheHeaderPyJWKClient("http://nonexist.com/.well-known/jwks.json")
    with pytest.raises(PyJWKClientError):
        client.fetch_data()


def test_fetch_data_error2(mocker):
    class ResponseObj:
        def __enter__(self):
            return CachedResponse(content='{"ok": FAIL}'.encode('utf8'), status_code=400)

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

    mocker.patch('requests_cache.CachedSession.get', return_value=ResponseObj())

    client = CacheHeaderPyJWKClient("http://nonexist.com/.well-known/jwks.json")
    with pytest.raises(PyJWKClientError):
        client.fetch_data()
