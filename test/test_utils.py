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
