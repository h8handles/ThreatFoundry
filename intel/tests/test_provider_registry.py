from unittest.mock import patch

from intel.services.provider_registry import (
    PROVIDER_SPECS,
    ProviderAvailability,
    build_provider_links,
    get_provider_spec,
    get_provider_availabilities,
)
from intel.services.ingestion import normalize_alienvault_record, normalize_urlhaus_record


def test_get_provider_spec():
    provider = "threatfox"
    spec = get_provider_spec(provider)
    assert spec is not None
    assert spec.key == provider
    assert spec.label == "ThreatFox"

def test_get_provider_spec_invalid():
    provider = "unknown"
    spec = get_provider_spec(provider)
    assert spec is None

def test_get_provider_availabilities():
    availabilities = get_provider_availabilities()
    assert len(availabilities) > 0
    for availability in availabilities:
        assert isinstance(availability, ProviderAvailability)

def test_build_provider_links_valid():
    value = "59.153.164.91"
    value_type = "ip"
    links = build_provider_links(
        "threatfox",
        value=value,
        value_type=value_type,
        source_record_id="12345",
    )
    assert len(links) > 0
    for link in links:
        assert isinstance(link, dict)
        assert set(link.keys()) >= {"provider", "label", "url", "note"}

def test_build_provider_links_invalid_provider():
    value = "59.153.164.91"
    value_type = "ip"
    links = build_provider_links("unknown", value=value, value_type=value_type)
    assert len(links) == 0

def test_build_provider_links_missing_env_vars():
    provider_spec = PROVIDER_SPECS["threatfox"]
    with patch.dict("os.environ", clear=True):
        availability = provider_spec.availability()
        assert not availability.enabled
        links = build_provider_links(provider_spec.key, value="59.153.164.91", value_type="ip")
        assert len(links) == 0

def test_normalize_alienvault_record_valid():
    record = {
        "id": "otx-123",
        "indicator": "evil.example",
        "type": "domain",
        "created": "2026-04-10T12:00:00",
        "modified": "2026-04-11T15:30:00",
        "pulse_info": {
            "pulses": [
                {
                    "name": "Credential phishing infrastructure",
                    "author_name": "OTX Research",
                    "tags": ["phishing", "credential-theft"],
                    "references": ["https://example.com/report"],
                }
            ]
        },
        "targeted_countries": ["US"],
    }

    normalized = normalize_alienvault_record(record)

    assert normalized["source_name"] == "alienvault"
    assert normalized["value"] == "evil.example"
    assert normalized["value_type"] == "domain"
    assert normalized["reporter"] == "OTX Research"
    assert normalized["reference_url"] == "https://example.com/report"
    assert normalized["tags"] == ["US", "phishing", "credential-theft"]
    assert normalized["first_seen"] is not None
    assert normalized["last_seen"] is not None

def test_normalize_alienvault_record_invalid():
    record = {
        "id": "otx-123",
        "indicator": None,
        "type": None,
        "created": None,
        "modified": None,
        "pulse_info": None,
        "targeted_countries": None,
    }

    normalized = normalize_alienvault_record(record)
    assert normalized is None

def test_normalize_urlhaus_record_valid():
    record = {
        "id": "555001",
        "url": "https://cdn.bad-download.example/payload.zip",
        "date_added": "2026-04-09 12:00:00",
        "last_online": "2026-04-10 15:30:00",
        "reporter": "abuse_ch",
        "url_status": "online",
        "threat": "malware_download",
        "signature": "SmokeLoader",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/555001/",
        "tags": ["download", "malware"],
    }

    normalized = normalize_urlhaus_record(record)

    assert normalized["source_name"] == "urlhaus"
    assert normalized["value_type"] == "url"
    assert normalized["value"] == "https://cdn.bad-download.example/payload.zip"
    assert normalized["reference_url"] == "https://urlhaus.abuse.ch/url/555001/"

def test_normalize_urlhaus_record_invalid():
    record = {
        "id": None,
        "url": None,
        "date_added": None,
        "last_online": None,
        "reporter": None,
        "url_status": None,
        "threat": None,
        "signature": None,
        "urlhaus_reference": None,
        "tags": None,
    }

    normalized = normalize_urlhaus_record(record)
    assert normalized is None
