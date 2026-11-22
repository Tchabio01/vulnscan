from unittest.mock import patch
from vulnscan import Finding


def test_check_headers_detects_missing(scanner, mock_response):
    with patch.object(scanner, "req", return_value=mock_response(headers={})):
        scanner.check_headers()
    names = [f.name for f in scanner.findings]
    assert any("HSTS" in n for n in names)


def test_check_lfi_ignores_static(scanner):
    scanner.check_lfi("http://x/style.css", {"id": "1"})
    assert not scanner.findings


def test_check_lfi_ignores_no_params(scanner):
    scanner.check_lfi("http://x/", {})
    assert not scanner.findings


def test_add_deduplicates(scanner):
    f1 = Finding("A", "LOW", "u", "e", "d", "r")
    f2 = Finding("A", "LOW", "u", "e", "d", "r")
    scanner.add(f1)
    scanner.add(f2)
    assert len(scanner.findings) == 1
