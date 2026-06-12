from datetime import datetime, timedelta
from functools import wraps
from uuid import uuid4

from authlib.jose import Key
from cryptography.hazmat.primitives import serialization
from flask import Response, current_app


def get_public_key_as_pem(key: Key):
    return key.as_pem()


def get_private_key_as_pem(key: Key):
    private_key = key.get_private_key()
    private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PrivateFormat.PKCS8,
                                                  encryption_algorithm=serialization.NoEncryption())
    return private_key_bytes


def new_trace_headers(trace_headers: dict, headers: dict = None):
    rv = {"X-Request-Id": str(uuid4())}
    if headers:
        rv.update(headers)
    if "X-Request-Id" in trace_headers:
        # No, this is not a typo, the X-Request-Id goes into X-Correlation-Id
        rv["X-Correlation-Id"] = trace_headers['X-Request-Id']
    if "X-Trace-Id" in trace_headers:
        rv["X-Trace-Id"] = trace_headers['X-Trace-Id']
    return rv


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


def oidc_smart_config_cached():
    """ Flask decorator that allow to set Expire and Cache headers. """

    def fwrap(f):
        @wraps(f)
        def wrapped_f(*args, **kwargs):
            seconds = current_app.config.get('OIDC_SMART_CONFIG_CACHING_SECONDS', 30)
            rsp: Response = f(*args, **kwargs)
            then = datetime.now() + timedelta(seconds=seconds)
            rsp.headers.add('Expires', then.strftime("%a, %d %b %Y %H:%M:%S GMT"))
            rsp.headers.add('Cache-Control', 'public,max-age=%d' % int(seconds))
            return rsp

        return wrapped_f

    return fwrap
