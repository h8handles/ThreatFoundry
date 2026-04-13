"""Tests for WHOIS client normalization and validation behavior."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from whois_client import lookup_domain_whois


def test_lookup_domain_whois_with_dict_response():
    sample = {
        "domain_name": ["example.com", "EXAMPLE.COM"],
        "registrar": "Example Registrar LLC",
        "creation_date": datetime(2020, 1, 1, 12, 0, 0),
        "expiration_date": [datetime(2030, 1, 1, 12, 0, 0)],
        "updated_date": datetime(2025, 1, 1, 12, 0, 0),
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "status": "active",
        "emails": None,
        "org": "Example Org",
        "country": "US",
    }

    with patch("whois_client.whois.whois", return_value=sample) as mock_lookup:
        result = lookup_domain_whois("example.com")

    mock_lookup.assert_called_once_with("example.com")
    assert result == {
        "domain_name": "example.com",
        "registrar": "Example Registrar LLC",
        "creation_date": "2020-01-01T12:00:00",
        "expiration_date": "2030-01-01T12:00:00",
        "updated_date": "2025-01-01T12:00:00",
        "name_servers": ["ns1.example.com", "ns2.example.com"],
        "status": ["active"],
        "emails": [],
        "organization": "Example Org",
        "country": "US",
    }


def test_lookup_domain_whois_with_attribute_response_and_org_fallback():
    raw = SimpleNamespace(
        domain_name="example.org",
        registrar="Registrar Two",
        creation_date=datetime(2021, 2, 2, 0, 0, 0),
        expiration_date=datetime(2031, 2, 2, 0, 0, 0),
        updated_date=None,
        name_servers="ns1.example.org",
        status=["ok"],
        emails="admin@example.org",
        org=None,
        registrant_organization="Fallback Org",
        country="CA",
    )

    with patch("whois_client.whois.whois", return_value=raw):
        result = lookup_domain_whois("example.org")

    assert result["domain_name"] == "example.org"
    assert result["name_servers"] == ["ns1.example.org"]
    assert result["emails"] == ["admin@example.org"]
    assert result["organization"] == "Fallback Org"
    assert result["country"] == "CA"


def test_lookup_domain_whois_rejects_invalid_domain():
    invalid_inputs = ["", "localhost", "not-a-domain", " "]

    for value in invalid_inputs:
        try:
            lookup_domain_whois(value)
            assert False, f"Expected ValueError for input: {value!r}"
        except ValueError as exc:
            assert "valid domain" in str(exc)


def test_lookup_domain_whois_propagates_lookup_exception():
    with patch("whois_client.whois.whois", side_effect=RuntimeError("timeout")):
        try:
            lookup_domain_whois("example.com")
            assert False, "Expected RuntimeError to propagate"
        except RuntimeError as exc:
            assert str(exc) == "timeout"
