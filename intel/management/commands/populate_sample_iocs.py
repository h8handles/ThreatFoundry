from __future__ import annotations

import json
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from intel.models import IntelIOC


SAMPLE_RECORD_PREFIX = "sample-"


def _build_large_payload() -> dict:
    long_content = "\n".join(
        f"payload-line-{index:04d}: suspicious execution trace and registry artifact"
        for index in range(220)
    )
    return {
        "id": "sample-otx-ip-59-153-164-91",
        "indicator": "59.153.164.91",
        "type": "ip",
        "title": "Long-form correlated source payload",
        "description": "Synthetic sample payload used to validate bounded scrolling in the IOC detail view.",
        "content": long_content,
        "pulse_info": {
            "pulses": [
                {
                    "name": "Coordinated delivery infrastructure",
                    "author_name": "OTX Sample Feed",
                    "tags": ["botnet", "payload-delivery", "sample"],
                    "references": [
                        "https://otx.alienvault.com/indicator/ip/59.153.164.91",
                        "https://otx.alienvault.com/pulse/6806c0d040dfc1b5f09f8f91",
                    ],
                }
            ]
        },
        "evidence": [
            {
                "kind": "network",
                "value": f"10.20.30.{index}",
            }
            for index in range(1, 25)
        ],
    }


def sample_ioc_payloads() -> list[dict]:
    now = timezone.now()
    large_payload = _build_large_payload()
    return [
        {
            "source_name": "threatfox",
            "source_record_id": f"{SAMPLE_RECORD_PREFIX}threatfox-ip-1",
            "value": "59.153.164.91",
            "value_type": "ip",
            "threat_type": "botnet_cc",
            "malware_family": "ClearFake",
            "confidence_level": 76,
            "first_seen": now - timedelta(days=3),
            "last_seen": now - timedelta(days=1, hours=4),
            "reporter": "abuse_ch",
            "reference_url": "https://threatfox.abuse.ch/ioc/900001/",
            "tags": ["botnet", "clearfake"],
            "external_references": [
                {
                    "provider": "threatfox",
                    "label": "ThreatFox record",
                    "url": "https://threatfox.abuse.ch/ioc/900001/",
                }
            ],
            "raw_payload": {
                "id": "sample-tf-1",
                "ioc": "59.153.164.91",
                "ioc_type": "ip",
                "malware_printable": "ClearFake",
                "confidence_level": 76,
                "reference": "https://threatfox.abuse.ch/ioc/900001/",
            },
            "enrichment_payloads": {},
            "last_enriched_at": None,
            "last_enrichment_providers": [],
        },
        {
            "source_name": "alienvault",
            "source_record_id": f"{SAMPLE_RECORD_PREFIX}alienvault-ip-1",
            "value": "59.153.164.91",
            "value_type": "ip",
            "threat_type": "malware",
            "malware_family": "",
            "confidence_level": None,
            "first_seen": now - timedelta(days=2, hours=2),
            "last_seen": now - timedelta(hours=8),
            "reporter": "OTX Sample Feed",
            "reference_url": "https://otx.alienvault.com/indicator/ip/59.153.164.91",
            "tags": ["sample", "long-payload"],
            "external_references": [
                {
                    "provider": "alienvault",
                    "label": "AlienVault OTX indicator",
                    "url": "https://otx.alienvault.com/indicator/ip/59.153.164.91",
                },
                {
                    "provider": "virustotal",
                    "label": "VirusTotal IP page",
                    "url": "https://www.virustotal.com/gui/ip-address/59.153.164.91/detection",
                    "note": "May require a VirusTotal sign-in for full context.",
                },
            ],
            "raw_payload": large_payload,
            "enrichment_payloads": {
                "virustotal": {
                    "provider": "virustotal",
                    "fetched_at": (now - timedelta(hours=2)).isoformat(),
                    "lookup": {
                        "object_type": "ip_address",
                        "platform_type": "ip",
                        "lookup_value": "59.153.164.91",
                        "display_value": "59.153.164.91",
                    },
                    "summary": {
                        "object_id": "59.153.164.91",
                        "object_type": "ip_address",
                        "reference_url": "https://www.virustotal.com/api/v3/ip_addresses/59.153.164.91",
                        "analysis_score": 82,
                        "popular_threat_categories": [{"label": "trojan", "count": 4}],
                        "popular_threat_names": [{"label": "ClearFake", "count": 4}],
                        "tags": ["botnet", "malware"],
                        "last_analysis_date": (now - timedelta(hours=5)).isoformat(),
                    },
                    "raw": {"sample": True, "payload_size": len(json.dumps(large_payload))},
                }
            },
            "last_enriched_at": now - timedelta(hours=2),
            "last_enrichment_providers": ["virustotal"],
        },
        {
            "source_name": "threatfox",
            "source_record_id": f"{SAMPLE_RECORD_PREFIX}threatfox-domain-1",
            "value": "signin-clearfake.example",
            "value_type": "domain",
            "threat_type": "phishing",
            "malware_family": "ClearFake",
            "confidence_level": 64,
            "first_seen": now - timedelta(days=4),
            "last_seen": now - timedelta(days=1),
            "reporter": "abuse_ch",
            "reference_url": "https://threatfox.abuse.ch/ioc/900002/",
            "tags": ["phishing", "credential-theft"],
            "external_references": [
                {
                    "provider": "threatfox",
                    "label": "ThreatFox record",
                    "url": "https://threatfox.abuse.ch/ioc/900002/",
                }
            ],
            "raw_payload": {
                "id": "sample-tf-domain-1",
                "ioc": "signin-clearfake.example",
                "ioc_type": "domain",
                "malware_printable": "ClearFake",
                "threat_type": "phishing",
                "reference": "https://threatfox.abuse.ch/ioc/900002/",
            },
            "enrichment_payloads": {},
            "last_enriched_at": None,
            "last_enrichment_providers": [],
        },
        {
            "source_name": "urlhaus",
            "source_record_id": f"{SAMPLE_RECORD_PREFIX}urlhaus-url-1",
            "value": "https://cdn.bad-download.example/payload.zip",
            "value_type": "url",
            "threat_type": "online",
            "malware_family": "SmokeLoader",
            "confidence_level": None,
            "first_seen": now - timedelta(days=5),
            "last_seen": now - timedelta(days=2),
            "reporter": "abuse_ch",
            "reference_url": "https://urlhaus.abuse.ch/url/900003/",
            "tags": ["urlhaus", "malware-download"],
            "external_references": [
                {
                    "provider": "urlhaus",
                    "label": "URLhaus URL record",
                    "url": "https://urlhaus.abuse.ch/url/900003/",
                }
            ],
            "raw_payload": {
                "id": "900003",
                "url": "https://cdn.bad-download.example/payload.zip",
                "url_status": "online",
                "threat": "malware_download",
                "signature": "SmokeLoader",
                "reporter": "abuse_ch",
            },
            "enrichment_payloads": {},
            "last_enriched_at": None,
            "last_enrichment_providers": [],
        },
        {
            "source_name": "alienvault",
            "source_record_id": f"{SAMPLE_RECORD_PREFIX}alienvault-hash-1",
            "value": "fd4b54bb92dd5c8cd056da618894816a",
            "value_type": "FileHash-MD5",
            "threat_type": "malware",
            "malware_family": "",
            "confidence_level": None,
            "first_seen": now - timedelta(days=2),
            "last_seen": now - timedelta(days=1),
            "reporter": "OTX Sample Feed",
            "reference_url": "https://otx.alienvault.com/indicator/file/fd4b54bb92dd5c8cd056da618894816a",
            "tags": ["hash", "malware"],
            "external_references": [
                {
                    "provider": "alienvault",
                    "label": "AlienVault OTX indicator",
                    "url": "https://otx.alienvault.com/indicator/file/fd4b54bb92dd5c8cd056da618894816a",
                },
                {
                    "provider": "virustotal",
                    "label": "VirusTotal file page",
                    "url": "https://www.virustotal.com/gui/file/fd4b54bb92dd5c8cd056da618894816a/detection",
                    "note": "May require a VirusTotal sign-in for full context.",
                },
            ],
            "raw_payload": {
                "id": 926,
                "indicator": "fd4b54bb92dd5c8cd056da618894816a",
                "type": "FileHash-MD5",
                "description": "Sample hash record for detail and provider-link validation.",
                "content": "",
            },
            "enrichment_payloads": {
                "virustotal": {
                    "provider": "virustotal",
                    "fetched_at": (now - timedelta(hours=3)).isoformat(),
                    "lookup": {
                        "object_type": "file",
                        "platform_type": "FileHash-MD5",
                        "lookup_value": "fd4b54bb92dd5c8cd056da618894816a",
                        "display_value": "fd4b54bb92dd5c8cd056da618894816a",
                    },
                    "summary": {
                        "object_id": "fd4b54bb92dd5c8cd056da618894816a",
                        "object_type": "file",
                        "reference_url": "https://www.virustotal.com/api/v3/files/fd4b54bb92dd5c8cd056da618894816a",
                        "analysis_score": 76,
                        "popular_threat_categories": [{"label": "trojan", "count": 6}],
                        "popular_threat_names": [{"label": "ClearFake", "count": 6}],
                        "tags": ["trojan", "downloader"],
                        "last_analysis_date": (now - timedelta(hours=6)).isoformat(),
                    },
                    "raw": {"sample": True, "kind": "hash"},
                }
            },
            "last_enriched_at": now - timedelta(hours=3),
            "last_enrichment_providers": ["virustotal"],
        },
        {
            "source_name": "threatfox",
            "source_record_id": f"{SAMPLE_RECORD_PREFIX}minimal-domain-1",
            "value": "minimal-example.test",
            "value_type": "domain",
            "threat_type": "",
            "malware_family": "",
            "confidence_level": None,
            "first_seen": None,
            "last_seen": None,
            "reporter": "",
            "reference_url": "",
            "tags": [],
            "external_references": [],
            "raw_payload": {},
            "enrichment_payloads": {},
            "last_enriched_at": None,
            "last_enrichment_providers": [],
        },
    ]


class Command(BaseCommand):
    help = (
        "Populate the database with realistic sample IOC records, including a large "
        "source payload, so the dashboard and detail views can be validated locally."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset-samples",
            action="store_true",
            help="Delete previously generated sample IOC records before repopulating them.",
        )

    def handle(self, *args, **options):
        if options["reset_samples"]:
            deleted, _ = IntelIOC.objects.filter(
                source_record_id__startswith=SAMPLE_RECORD_PREFIX
            ).delete()
            self.stdout.write(self.style.WARNING(f"Deleted {deleted} existing sample record(s)."))

        created = 0
        updated = 0
        for payload in sample_ioc_payloads():
            _, was_created = IntelIOC.objects.update_or_create(
                source_name=payload["source_name"],
                source_record_id=payload["source_record_id"],
                defaults=payload,
            )
            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(
            self.style.SUCCESS(
                "Sample IOC population complete "
                f"(created={created}, updated={updated}, total_samples={len(sample_ioc_payloads())})."
            )
        )
