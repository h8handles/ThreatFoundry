from unittest.mock import patch

from django.test import SimpleTestCase

from intel.services.ingestion import normalize_alienvault_record, normalize_urlhaus_record
from intel.services.provider_registry import (
    PROVIDER_SPECS,
    ProviderAvailability,
    build_provider_links,
    get_provider_availabilities,
    get_provider_spec,
)


class ProviderRegistryModuleTests(SimpleTestCase):
    def test_get_provider_spec(self):
        provider = "threatfox"
        spec = get_provider_spec(provider)
        self.assertIsNotNone(spec)
        self.assertEqual(spec.key, provider)
        self.assertEqual(spec.label, "ThreatFox")

    def test_get_provider_spec_invalid(self):
        provider = "unknown"
        spec = get_provider_spec(provider)
        self.assertIsNone(spec)

    def test_get_provider_availabilities(self):
        availabilities = get_provider_availabilities()
        self.assertGreater(len(availabilities), 0)
        for availability in availabilities:
            self.assertIsInstance(availability, ProviderAvailability)

    def test_build_provider_links_valid(self):
        value = "59.153.164.91"
        value_type = "ip"
        links = build_provider_links(
            "threatfox",
            value=value,
            value_type=value_type,
            source_record_id="12345",
        )
        self.assertGreater(len(links), 0)
        for link in links:
            self.assertIsInstance(link, dict)
            self.assertTrue(set(link.keys()) >= {"provider", "label", "url", "note"})

    def test_build_provider_links_invalid_provider(self):
        value = "59.153.164.91"
        value_type = "ip"
        links = build_provider_links("unknown", value=value, value_type=value_type)
        self.assertEqual(len(links), 0)

    def test_build_provider_links_missing_env_vars(self):
        provider_spec = PROVIDER_SPECS["threatfox"]
        with patch.dict("os.environ", clear=True):
            availability = provider_spec.availability()
            self.assertFalse(availability.enabled)
            links = build_provider_links(
                provider_spec.key,
                value="59.153.164.91",
                value_type="ip",
            )
            self.assertEqual(len(links), 0)

    def test_normalize_alienvault_record_valid(self):
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

        self.assertEqual(normalized["source_name"], "alienvault")
        self.assertEqual(normalized["value"], "evil.example")
        self.assertEqual(normalized["value_type"], "domain")
        self.assertEqual(normalized["reporter"], "OTX Research")
        self.assertEqual(normalized["reference_url"], "https://example.com/report")
        self.assertEqual(normalized["tags"], ["US", "phishing", "credential-theft"])
        self.assertIsNotNone(normalized["first_seen"])
        self.assertIsNotNone(normalized["last_seen"])

    def test_normalize_alienvault_record_invalid(self):
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
        self.assertIsNone(normalized)

    def test_normalize_urlhaus_record_valid(self):
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

        self.assertEqual(normalized["source_name"], "urlhaus")
        self.assertEqual(normalized["value_type"], "url")
        self.assertEqual(
            normalized["value"],
            "https://cdn.bad-download.example/payload.zip",
        )
        self.assertEqual(
            normalized["reference_url"],
            "https://urlhaus.abuse.ch/url/555001/",
        )

    def test_normalize_urlhaus_record_invalid(self):
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
        self.assertIsNone(normalized)
