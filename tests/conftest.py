import pytest
from unittest.mock import Mock
from vulnscan import VulnScanner, Finding


@pytest.fixture
def scanner():
    return VulnScanner("http://example.test", delay=0, timeout=2)


@pytest.fixture
def mock_response():
    def _make(status=200, text="", headers=None, cookies=None):
        r = Mock()
        r.status_code = status
        r.text = text
        r.content = text.encode()
        r.headers = headers or {}
        r.cookies = cookies or []
        r.elapsed.total_seconds.return_value = 0.1
        return r
    return _make
