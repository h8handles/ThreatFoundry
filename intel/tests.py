import json
from io import StringIO
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from intel.models import IngestionRun, IntelIOC, ProviderRun, ProviderRunDetail
from intel.management.commands.populate_sample_iocs import sample_ioc_payloads
from intel.services.correlation import build_hash_correlation_context, canonical_hash_type
from intel.services.dashboard import (
    DashboardFilters,
    build_dashboard_context,
    build_detail_context,
    build_ioc_blade_detail_context,
    build_malware_family_context,
    build_provider_health_status,
)
from intel.services.ingestion import normalize_alienvault_record, normalize_urlhaus_record, upsert_iocs
from intel.services.provider_registry import build_provider_links, get_provider_availabilities
from intel.services.provider_runs import ProviderRunRecorder
from intel.tests_provider_registry import ProviderRegistryModuleTests
from intel.services.virustotal import build_virustotal_enrichment, derive_platform_updates
from intel.time_display import TIME_DISPLAY_SESSION_KEY


class AlienVaultNormalizationTests(SimpleTestCase):
    def test_normalize_alienvault_record_maps_common_fields(self):
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

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["source_name"], "alienvault")
        self.assertEqual(normalized["source_record_id"], "otx-123")
        self.assertEqual(normalized["value"], "evil.example")
        self.assertEqual(normalized["value_type"], "domain")
        self.assertEqual(
            normalized["threat_type"], "Credential phishing infrastructure"
        )
        self.assertEqual(normalized["reporter"], "OTX Research")
        self.assertEqual(normalized["reference_url"], "https://example.com/report")
        self.assertEqual(
            normalized["tags"], ["US", "phishing", "credential-theft"]
        )
        self.assertIsNotNone(normalized["first_seen"])
        self.assertIsNotNone(normalized["last_seen"])

    def test_hash_type_aliases_normalize_across_sources(self):
        self.assertEqual(canonical_hash_type("FileHash-MD5"), "md5")
        self.assertEqual(canonical_hash_type("FileHash-SHA1"), "sha1")
        self.assertEqual(canonical_hash_type("FileHash-SHA256"), "sha256")
        self.assertEqual(canonical_hash_type("sha256_hash"), "sha256")
        self.assertIsNone(canonical_hash_type("domain"))

    def test_normalize_urlhaus_record_maps_common_fields(self):
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

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["source_name"], "urlhaus")
        self.assertEqual(normalized["value_type"], "url")
        self.assertEqual(normalized["value"], "https://cdn.bad-download.example/payload.zip")
        self.assertEqual(normalized["reference_url"], "https://urlhaus.abuse.ch/url/555001/")
        self.assertEqual(normalized["external_references"][0]["provider"], "urlhaus")


class ImportAlienVaultCommandTests(TestCase):
    @patch.dict("os.environ", {"OTX_API_KEY": "test-otx-key", "ALIENVAULT_ENABLED": "true"}, clear=False)
    @patch("intel.management.commands.import_alienvault.fetch_otx_iocs")
    def test_import_alienvault_command_upserts_records(self, mock_fetch):
        mock_fetch.return_value = {
            "results": [
                {
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
                                "tags": ["phishing"],
                                "references": ["https://example.com/report"],
                            }
                        ]
                    },
                }
            ]
        }

        stdout = StringIO()
        call_command("import_alienvault", days=1, stdout=stdout)

        self.assertEqual(IntelIOC.objects.count(), 1)
        record = IntelIOC.objects.get()
        self.assertEqual(record.source_name, "alienvault")
        self.assertEqual(record.value, "evil.example")
        provider_run = ProviderRun.objects.get()
        self.assertEqual(provider_run.provider_name, "alienvault")
        self.assertEqual(provider_run.run_type, ProviderRun.RunType.INGEST)
        self.assertEqual(provider_run.status, ProviderRun.Status.SUCCESS)
        self.assertEqual(provider_run.records_fetched, 1)
        self.assertEqual(provider_run.records_created, 1)
        self.assertIn("AlienVault import complete", stdout.getvalue())


class RefreshIntelCommandTests(TestCase):
    @patch.dict(
        "os.environ",
        {
            "THREATFOX_API_KEY": "test-threatfox-key",
            "OTX_API_KEY": "test-otx-key",
            "URLHAUS_ENABLED": "true",
            "VIRUSTOTAL_ENABLED": "false",
        },
        clear=False,
    )
    @patch("intel.services.refresh_pipeline.fetch_recent_urlhaus_iocs")
    @patch("intel.services.refresh_pipeline.fetch_otx_iocs")
    @patch("intel.services.refresh_pipeline.fetch_threatfox_iocs")
    def test_refresh_intel_runs_enabled_ingestion_providers_and_records_history(
        self,
        mock_threatfox,
        mock_otx,
        mock_urlhaus,
    ):
        mock_threatfox.return_value = {
            "data": [
                {
                    "id": "tf-1",
                    "ioc": "59.153.164.91",
                    "ioc_type": "ip",
                    "first_seen": "2026-04-10 12:00:00",
                    "last_seen": "2026-04-11 15:00:00",
                    "reference": "https://threatfox.abuse.ch/ioc/tf-1/",
                }
            ]
        }
        mock_otx.return_value = {
            "results": [
                {
                    "id": "otx-1",
                    "indicator": "evil.example",
                    "type": "domain",
                    "created": "2026-04-10T12:00:00",
                    "modified": "2026-04-11T15:30:00",
                }
            ]
        }
        mock_urlhaus.return_value = {
            "urls": [
                {
                    "id": "urlhaus-1",
                    "url": "https://bad.example/payload.zip",
                    "date_added": "2026-04-10 12:00:00",
                    "last_online": "2026-04-11 14:30:00",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/urlhaus-1/",
                }
            ]
        }

        stdout = StringIO()
        call_command("refresh_intel", stdout=stdout)

        self.assertEqual(IntelIOC.objects.count(), 3)
        run = IngestionRun.objects.get()
        self.assertEqual(run.status, IngestionRun.Status.SUCCESS)
        self.assertGreaterEqual(run.providers_total, 3)
        self.assertTrue(run.feed_refreshed)
        self.assertEqual(run.records_created, 3)
        self.assertGreaterEqual(run.provider_details.count(), 3)
        self.assertTrue(
            {"threatfox", "alienvault", "urlhaus"}.issubset(
                set(run.provider_details.values_list("provider_name", flat=True))
            )
        )
        self.assertIn("refresh_intel complete", stdout.getvalue())

    @patch.dict("os.environ", {"THREATFOX_API_KEY": "test-threatfox-key"}, clear=False)
    @patch("intel.services.refresh_pipeline.fetch_threatfox_iocs")
    def test_refresh_intel_dry_run_does_not_persist_iocs(self, mock_threatfox):
        mock_threatfox.return_value = {
            "data": [
                {
                    "id": "tf-1",
                    "ioc": "dry-run.example",
                    "ioc_type": "domain",
                }
            ]
        }

        call_command("refresh_intel", provider="threatfox", dry_run=True)

        self.assertEqual(IntelIOC.objects.count(), 0)
        run = IngestionRun.objects.get()
        detail = ProviderRunDetail.objects.get(ingestion_run=run)
        self.assertTrue(run.dry_run)
        self.assertEqual(detail.records_created, 1)

    @patch.dict(
        "os.environ",
        {
            "THREATFOX_API_KEY": "test-threatfox-key",
            "OTX_API_KEY": "test-otx-key",
            "URLHAUS_ENABLED": "false",
            "VIRUSTOTAL_ENABLED": "false",
        },
        clear=False,
    )
    @patch("intel.services.refresh_pipeline.fetch_otx_iocs")
    @patch("intel.services.refresh_pipeline.fetch_threatfox_iocs")
    def test_refresh_intel_continues_when_one_provider_fails(
        self,
        mock_threatfox,
        mock_otx,
    ):
        mock_threatfox.side_effect = RuntimeError("ThreatFox timeout")
        mock_otx.return_value = {
            "results": [
                {
                    "id": "otx-1",
                    "indicator": "evil.example",
                    "type": "domain",
                    "created": "2026-04-10T12:00:00",
                    "modified": "2026-04-11T15:30:00",
                }
            ]
        }

        stdout = StringIO()
        call_command("refresh_intel", provider=None, stdout=stdout)

        self.assertEqual(IntelIOC.objects.count(), 1)
        run = IngestionRun.objects.get()
        self.assertEqual(run.status, IngestionRun.Status.PARTIAL)
        self.assertEqual(run.providers_failed, 1)
        self.assertEqual(
            ProviderRunDetail.objects.get(provider_name="threatfox").status,
            ProviderRunDetail.Status.FAILURE,
        )
        self.assertEqual(
            ProviderRunDetail.objects.get(provider_name="alienvault").status,
            ProviderRunDetail.Status.SUCCESS,
        )


class ProviderRegistryTests(SimpleTestCase):
    def test_build_provider_links_uses_real_supported_patterns(self):
        threatfox_links = build_provider_links(
            "threatfox",
            value="59.153.164.91",
            value_type="ip",
            source_record_id="900001",
        )
        otx_links = build_provider_links(
            "alienvault",
            value="59.153.164.91",
            value_type="ip",
        )
        urlhaus_links = build_provider_links(
            "urlhaus",
            value="https://cdn.bad-download.example/payload.zip",
            value_type="url",
            source_record_id="555001",
        )
        vt_links = build_provider_links(
            "virustotal",
            value="59.153.164.91",
            value_type="ip",
            enrichment_summary={
                "object_type": "ip_address",
                "object_id": "59.153.164.91",
            },
        )

        self.assertEqual(
            threatfox_links[0]["url"],
            "https://threatfox.abuse.ch/ioc/900001/",
        )
        self.assertEqual(
            otx_links[0]["url"],
            "https://otx.alienvault.com/indicator/ip/59.153.164.91",
        )
        self.assertEqual(
            urlhaus_links[0]["url"],
            "https://urlhaus.abuse.ch/url/555001/",
        )
        self.assertEqual(
            vt_links[0]["url"],
            "https://www.virustotal.com/gui/ip-address/59.153.164.91/detection",
        )
        self.assertIn("sign-in", vt_links[0]["note"].lower())

    def test_build_provider_links_returns_empty_for_unknown_provider(self):
        self.assertEqual(
            build_provider_links("unknown", value="example.test", value_type="domain"),
            [],
        )

    @patch.dict(
        "os.environ",
        {
            "THREATFOX_API_KEY": "",
            "OTX_API_KEY": "",
            "VIRUSTOTAL_API_KEY": "",
            "ABUSEIPDB_API_KEY": "",
            "SHODAN_API_KEY": "",
            "URLHAUS_ENABLED": "true",
        },
        clear=False,
    )
    def test_provider_availability_handles_missing_keys_gracefully(self):
        availability = {item.key: item for item in get_provider_availabilities()}

        self.assertFalse(availability["threatfox"].enabled)
        self.assertFalse(availability["alienvault"].enabled)
        self.assertFalse(availability["virustotal"].enabled)
        self.assertTrue(availability["urlhaus"].enabled)


class ProviderRunRecorderTests(TestCase):
    def test_provider_run_recorder_marks_success_with_counts(self):
        recorder = ProviderRunRecorder.start(
            provider_name="threatfox",
            run_type=ProviderRun.RunType.INGEST,
            enabled_state=True,
            details={"days": 1},
        )

        recorder.mark_success(
            records_fetched=10,
            records_created=4,
            records_updated=5,
            records_skipped=1,
        )

        run = ProviderRun.objects.get()
        self.assertEqual(run.provider_name, "threatfox")
        self.assertEqual(run.status, ProviderRun.Status.SUCCESS)
        self.assertTrue(run.enabled_state)
        self.assertEqual(run.records_fetched, 10)
        self.assertEqual(run.records_created, 4)
        self.assertEqual(run.records_updated, 5)
        self.assertEqual(run.records_skipped, 1)
        self.assertIsNotNone(run.completed_at)
        self.assertEqual(run.details["days"], 1)

    @patch("intel.services.provider_runs.logger.info")
    def test_provider_run_recorder_emits_structured_success_log(self, mock_log_info):
        recorder = ProviderRunRecorder.start(
            provider_name="threatfox",
            run_type=ProviderRun.RunType.INGEST,
            enabled_state=True,
        )
        recorder.mark_success(
            records_fetched=2,
            records_created=1,
            records_updated=1,
            records_skipped=0,
        )

        self.assertGreaterEqual(mock_log_info.call_count, 2)
        logged = [json.loads(call.args[0]) for call in mock_log_info.call_args_list]
        final_event = next(item for item in logged if item["event"] == "provider_run_finished")
        self.assertEqual(final_event["provider"], "threatfox")
        self.assertEqual(final_event["status"], ProviderRun.Status.SUCCESS)
        self.assertEqual(final_event["records_fetched"], 2)
        self.assertEqual(final_event["records_created"], 1)
        self.assertEqual(final_event["records_updated"], 1)
        self.assertEqual(final_event["records_skipped"], 0)
        self.assertIn("timestamp", final_event)
        self.assertIsNotNone(final_event["duration_seconds"])

    def test_provider_run_recorder_marks_failure_with_error_message(self):
        recorder = ProviderRunRecorder.start(
            provider_name="virustotal",
            run_type=ProviderRun.RunType.ENRICHMENT,
            enabled_state=False,
        )

        recorder.mark_failure(
            error_message="VirusTotal API key not found. Set VIRUSTOTAL_API_KEY in your environment.",
            records_fetched=0,
            records_updated=0,
            records_skipped=0,
        )

        run = ProviderRun.objects.get()
        self.assertEqual(run.status, ProviderRun.Status.FAILURE)
        self.assertIn("VirusTotal API key not found", run.last_error_message)
        self.assertIsNotNone(run.completed_at)

    @patch("intel.services.provider_runs.logger.info")
    def test_provider_run_recorder_emits_structured_failure_log(self, mock_log_info):
        recorder = ProviderRunRecorder.start(
            provider_name="virustotal",
            run_type=ProviderRun.RunType.ENRICHMENT,
            enabled_state=True,
        )
        recorder.mark_failure(
            error_message="VirusTotal timed out",
            error_type="TimeoutError",
            records_fetched=3,
            records_updated=0,
            records_skipped=3,
        )

        logged = [json.loads(call.args[0]) for call in mock_log_info.call_args_list]
        final_event = next(item for item in logged if item["event"] == "provider_run_finished")
        self.assertEqual(final_event["provider"], "virustotal")
        self.assertEqual(final_event["status"], ProviderRun.Status.FAILURE)
        self.assertEqual(final_event["error_type"], "TimeoutError")
        self.assertIn("VirusTotal timed out", final_event["error_message"])
        self.assertEqual(final_event["records_fetched"], 3)
        self.assertEqual(final_event["records_skipped"], 3)


class IngestionStructuredLoggingTests(TestCase):
    @patch("intel.services.ingestion.logger.info")
    def test_upsert_iocs_emits_structured_success_log(self, mock_log_info):
        records = [{"id": "tf-1", "ioc": "example.com", "ioc_type": "domain"}]
        result = upsert_iocs(records, provider_name="threatfox", dry_run=True)

        self.assertEqual(result.created, 1)
        self.assertEqual(result.updated, 0)
        self.assertEqual(result.skipped, 0)
        payload = json.loads(mock_log_info.call_args.args[0])
        self.assertEqual(payload["event"], "ingestion_upsert_finished")
        self.assertEqual(payload["provider"], "threatfox")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["records_fetched"], 1)
        self.assertEqual(payload["records_created"], 1)
        self.assertIn("timestamp", payload)
        self.assertIsNotNone(payload["duration_seconds"])

    @patch("intel.services.ingestion.logger.info")
    def test_upsert_iocs_emits_structured_failure_log(self, mock_log_info):
        def bad_normalizer(_record):
            raise ValueError("bad record")

        with self.assertRaises(ValueError):
            upsert_iocs([{"id": "bad"}], normalizer=bad_normalizer, provider_name="threatfox", dry_run=True)

        payload = json.loads(mock_log_info.call_args.args[0])
        self.assertEqual(payload["event"], "ingestion_upsert_failed")
        self.assertEqual(payload["provider"], "threatfox")
        self.assertEqual(payload["status"], "failure")
        self.assertEqual(payload["error_type"], "ValueError")
        self.assertIn("bad record", payload["error_message"])


class AlienVaultPresentationTests(TestCase):
    def test_provider_health_logic_and_dashboard_rendering(self):
        now = datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc)
        ProviderRun.objects.create(
            provider_name="threatfox",
            run_type=ProviderRun.RunType.INGEST,
            status=ProviderRun.Status.SUCCESS,
            enabled_state=True,
            started_at=now,
            completed_at=now,
            records_fetched=5,
            records_created=5,
        )
        ProviderRunDetail.objects.create(
            ingestion_run=IngestionRun.objects.create(
                status=IngestionRun.Status.FAILURE,
                trigger="manual",
                requested_provider="alienvault",
                requested_since="24h",
                timeout_seconds=30,
                dry_run=False,
                feed_refreshed=False,
                started_at=now,
            ),
            provider_name="alienvault",
            run_type=ProviderRunDetail.RunType.INGEST,
            enabled_state=True,
            status=ProviderRunDetail.Status.FAILURE,
            started_at=now,
            finished_at=now,
            error_summary="AlienVault timeout",
        )
        stale_then = datetime(2026, 4, 10, 9, 0, tzinfo=timezone.utc)
        ProviderRun.objects.create(
            provider_name="urlhaus",
            run_type=ProviderRun.RunType.INGEST,
            status=ProviderRun.Status.SUCCESS,
            enabled_state=True,
            started_at=stale_then,
            completed_at=stale_then,
            records_fetched=2,
            records_created=2,
        )
        ProviderRun.objects.create(
            provider_name="nvd",
            run_type=ProviderRun.RunType.INGEST,
            status=ProviderRun.Status.SKIPPED,
            enabled_state=True,
            started_at=now,
            completed_at=now,
            records_fetched=0,
            records_created=0,
        )

        with patch("intel.services.dashboard.timezone.now", return_value=now + timedelta(hours=30)):
            health_rows = build_provider_health_status()

        by_key = {item["key"]: item for item in health_rows}
        self.assertEqual(by_key["threatfox"]["health_state"], "stale")
        self.assertEqual(by_key["alienvault"]["health_state"], "failing")
        self.assertEqual(by_key["urlhaus"]["health_state"], "stale")
        self.assertEqual(by_key["nvd"]["health_state"], "warning")

        response = self.client.get(reverse("intel:dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Provider Health")
        self.assertIn("provider_health", response.context)

    def test_dashboard_uses_newest_source_timestamp_for_observed_at(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="freshness-1",
            value="freshness.example",
            value_type="domain",
            first_seen=datetime(2026, 4, 10, 1, 0, tzinfo=timezone.utc),
            last_seen=datetime(2026, 4, 11, 5, 30, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 11, 6, 0, tzinfo=timezone.utc),
        )

        context = build_dashboard_context(
            DashboardFilters(
                start_date=None,
                end_date=None,
                value_type="",
                malware_family="",
                threat_type="",
                confidence_band="",
                search="freshness.example",
                tag="",
                page=1,
                page_size=25,
            )
        )

        self.assertEqual(
            context["recent_ioc_rows"][0]["observed_at"],
            datetime(2026, 4, 11, 5, 30, tzinfo=timezone.utc),
        )

    def test_dashboard_context_uses_source_aware_alienvault_summary(self):
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="931",
            value="3515daf08a5daa104a8be3169d64bef2",
            value_type="FileHash-MD5",
            raw_payload={
                "id": 931,
                "indicator": "3515daf08a5daa104a8be3169d64bef2",
                "type": "FileHash-MD5",
                "title": None,
                "description": None,
                "content": "",
            },
            first_seen=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
        )

        context = build_dashboard_context(
            DashboardFilters(
                start_date=None,
                end_date=None,
                value_type="",
                malware_family="",
                threat_type="",
                confidence_band="",
                search="",
                tag="",
                page=1,
                page_size=25,
            )
        )

        row = context["recent_ioc_rows"][0]
        self.assertEqual(row["summary_title"], "OTX indicator record")
        self.assertIn("Record ID 931", row["summary_meta"])
        self.assertEqual(row["type_label"], "FileHash-MD5")

    def test_detail_context_exposes_alienvault_raw_payload_sections(self):
        record = IntelIOC(
            source_name="alienvault",
            source_record_id="931",
            value="3515daf08a5daa104a8be3169d64bef2",
            value_type="FileHash-MD5",
            raw_payload={
                "id": 931,
                "indicator": "3515daf08a5daa104a8be3169d64bef2",
                "type": "FileHash-MD5",
                "title": None,
                "description": None,
                "content": "",
            },
            last_ingested_at=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
            created_at=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
        )

        context = build_detail_context(record)

        self.assertEqual(context["overview_items"][0]["label"], "IOC Type")
        self.assertEqual(context["detail_sections"][0]["title"], "OTX Record Fields")
        self.assertEqual(
            context["detail_sections"][0]["items"][0]["value"],
            "3515daf08a5daa104a8be3169d64bef2",
        )
        self.assertEqual(
            context["detail_sections"][1]["items"][0]["value"],
            "Not provided",
        )

    def test_dashboard_context_paginates_recent_iocs(self):
        for index in range(30):
            IntelIOC.objects.create(
                source_name="threatfox",
                source_record_id=f"ioc-{index}",
                value=f"example-{index}.com",
                value_type="domain",
                malware_family="ClearFake",
                threat_type="payload_delivery",
                last_ingested_at=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
            )

        context = build_dashboard_context(
            DashboardFilters(
                start_date=None,
                end_date=None,
                value_type="",
                malware_family="",
                threat_type="",
                confidence_band="",
                search="",
                tag="",
                page=2,
                page_size=10,
            )
        )

        self.assertEqual(len(context["recent_ioc_rows"]), 10)
        self.assertEqual(context["pagination"]["page_number"], 2)
        self.assertTrue(context["pagination"]["has_previous"])
        self.assertTrue(context["pagination"]["has_next"])

    def test_build_malware_family_context_returns_cluster_data(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="cluster-1",
            value="run-svc.athleticscrew.in.net",
            value_type="domain",
            malware_family="ClearFake",
            threat_type="payload_delivery",
            reporter="anonymous",
            reference_url="https://malpedia.example/clearfake",
            tags=["ClearFake"],
            raw_payload={
                "ioc_type_desc": "Domain name that delivers a malware payload",
                "threat_type_desc": "Indicator that identifies a malware distribution server",
                "malware_malpedia": "https://malpedia.example/clearfake",
            },
            first_seen=datetime(2026, 4, 10, 2, 39, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
        )

        context = build_malware_family_context("ClearFake", page=1, page_size=10)

        self.assertEqual(context["family"], "ClearFake")
        self.assertEqual(context["family_summary"]["total_iocs"], 1)
        self.assertEqual(context["family_type_distribution"]["labels"], ["domain"])
        self.assertEqual(context["related_ioc_rows"][0]["summary_title"], "payload_delivery")
        self.assertTrue(context["family_references"])

    def test_confidence_distribution_excludes_unscored_alienvault_rows(self):
        for index in range(3):
            IntelIOC.objects.create(
                source_name="alienvault",
                source_record_id=f"otx-{index}",
                value=f"hash-{index}",
                value_type="FileHash-MD5",
                confidence_level=None,
            )

        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="tf-1",
            value="clearfake.example",
            value_type="domain",
            malware_family="ClearFake",
            threat_type="payload_delivery",
            confidence_level=100,
        )

        context = build_dashboard_context(
            DashboardFilters(
                start_date=None,
                end_date=None,
                value_type="",
                malware_family="",
                threat_type="",
                confidence_band="",
                search="",
                tag="",
                page=1,
                page_size=25,
            )
        )

        distribution = dict(
            zip(
                context["confidence_distribution"]["labels"],
                context["confidence_distribution"]["values"],
            )
        )
        self.assertEqual(distribution["Unknown"], 0)
        self.assertEqual(distribution["75-100"], 1)

    def test_hash_correlation_infers_family_from_exact_threatfox_match(self):
        alien_record = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="otx-hash-1",
            value="ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
            value_type="FileHash-SHA256",
        )
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="tf-hash-1",
            value="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            value_type="sha256_hash",
            malware_family="ClearFake",
            threat_type="payload",
            reporter="threatcat_ch",
        )

        context = build_hash_correlation_context(alien_record)

        self.assertTrue(context["applicable"])
        self.assertEqual(context["canonical_type"], "SHA256")
        self.assertEqual(len(context["matches"]), 1)
        self.assertEqual(context["families"][0]["label"], "ClearFake")
        self.assertEqual(context["threat_types"][0]["label"], "payload")

    def test_dashboard_context_builds_one_ioc_blade_with_all_sources(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="tf-ip-1",
            value="59.153.164.91",
            value_type="ip",
            threat_type="botnet_cc",
            reference_url="https://threatfox.example/ip",
            last_ingested_at=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
        )
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="otx-ip-1",
            value="59.153.164.91",
            value_type="ip",
            threat_type="malware",
            enrichment_payloads={
                "virustotal": {
                    "summary": {
                        "object_id": "59.153.164.91",
                        "reference_url": "https://virustotal.example/ip/59.153.164.91",
                        "analysis_score": 82,
                        "popular_threat_categories": [{"label": "trojan", "count": 4}],
                        "popular_threat_names": [{"label": "ClearFake", "count": 4}],
                        "tags": ["botnet"],
                        "last_analysis_date": "2026-04-11T10:30:00+00:00",
                    }
                }
            },
            last_ingested_at=datetime(2026, 4, 11, 13, 49, tzinfo=timezone.utc),
        )

        context = build_dashboard_context(
            DashboardFilters(
                start_date=None,
                end_date=None,
                value_type="",
                malware_family="",
                threat_type="",
                confidence_band="",
                search="59.153.164.91",
                tag="",
                page=1,
                page_size=25,
            )
        )

        self.assertEqual(len(context["ioc_blades"]), 1)
        blade = context["ioc_blades"][0]
        self.assertEqual(blade["value"], "59.153.164.91")
        self.assertEqual(blade["record_count"], 2)
        self.assertIn("ThreatFox", blade["source_labels"])
        self.assertIn("AlienVault", blade["source_labels"])
        self.assertIn("VirusTotal", blade["source_labels"])

    def test_ioc_blade_detail_context_groups_references_by_source(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="tf-ip-1",
            value="59.153.164.91",
            value_type="ip",
            threat_type="botnet_cc",
            reporter="abuse_ch",
            reference_url="https://threatfox.example/ip",
            tags=["botnet"],
            last_ingested_at=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
        )
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="otx-ip-1",
            value="59.153.164.91",
            value_type="ip",
            enrichment_payloads={
                "virustotal": {
                    "summary": {
                        "object_id": "59.153.164.91",
                        "reference_url": "https://virustotal.example/ip/59.153.164.91",
                        "analysis_score": 82,
                        "popular_threat_categories": [{"label": "trojan", "count": 4}],
                        "popular_threat_names": [{"label": "ClearFake", "count": 4}],
                        "tags": ["malware"],
                        "last_analysis_date": "2026-04-11T10:30:00+00:00",
                    }
                }
            },
            last_ingested_at=datetime(2026, 4, 11, 13, 49, tzinfo=timezone.utc),
        )

        context = build_ioc_blade_detail_context("59.153.164.91", "ip")

        self.assertIsNotNone(context)
        self.assertEqual(context["source_count"], 3)
        source_map = {item["source_label"]: item for item in context["source_details"]}
        self.assertIn("ThreatFox", source_map)
        self.assertIn("AlienVault", source_map)
        self.assertIn("VirusTotal", source_map)
        self.assertEqual(
            source_map["ThreatFox"]["references"],
            ["https://threatfox.example/ip"],
        )
        self.assertEqual(
            source_map["VirusTotal"]["references"],
            ["https://www.virustotal.com/gui/ip-address/59.153.164.91/detection"],
        )


class VirusTotalEnrichmentTests(TestCase):
    def test_build_virustotal_enrichment_extracts_summary_and_platform_updates(self):
        payload = {
            "data": {
                "id": "abcd1234",
                "type": "file",
                "links": {"self": "https://www.virustotal.com/api/v3/files/abcd1234"},
                "attributes": {
                    "meaningful_name": "payload.exe",
                    "names": ["payload.exe", "dropper.exe"],
                    "type_description": "Win32 EXE",
                    "last_analysis_stats": {
                        "harmless": 10,
                        "malicious": 6,
                        "suspicious": 2,
                        "undetected": 2,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.clearfake",
                        "popular_threat_name": [{"value": "ClearFake", "count": 4}],
                        "popular_threat_category": [{"value": "trojan", "count": 4}],
                    },
                    "sandbox_verdicts": {
                        "VirusTotal Jujubox": {
                            "confidence": 83,
                            "malware_names": ["ClearFake"],
                            "malware_classification": ["TROJAN"],
                        }
                    },
                    "tags": ["trojan", "stealer"],
                    "sha256": "abcd1234",
                    "md5": "deadbeef",
                },
            }
        }

        enrichment = build_virustotal_enrichment(
            "deadbeef",
            "FileHash-MD5",
            payload,
        )
        updates = derive_platform_updates(enrichment)

        self.assertEqual(enrichment["summary"]["object_type"], "file")
        self.assertEqual(enrichment["summary"]["meaningful_name"], "payload.exe")
        self.assertEqual(enrichment["summary"]["detection_ratio"], "8/20")
        self.assertEqual(updates["malware_family"], "ClearFake")
        self.assertEqual(updates["threat_type"], "trojan")
        self.assertEqual(updates["confidence_level"], 35)
        self.assertEqual(updates["tags"], ["trojan", "stealer"])

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-vt-key", "VIRUSTOTAL_ENABLED": "true"}, clear=False)
    @patch("intel.management.commands.import_virustotal.throttle_request")
    @patch("intel.services.virustotal.fetch_virustotal_report")
    def test_import_virustotal_command_enriches_existing_iocs(
        self,
        mock_fetch,
        mock_throttle,
    ):
        mock_fetch.return_value = {
            "data": {
                "id": "3515daf08a5daa104a8be3169d64bef2",
                "type": "file",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/files/3515daf08a5daa104a8be3169d64bef2"
                },
                "attributes": {
                    "meaningful_name": "dropper.exe",
                    "last_analysis_stats": {
                        "harmless": 2,
                        "malicious": 12,
                        "suspicious": 2,
                        "undetected": 4,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.clearfake",
                        "popular_threat_name": [{"value": "ClearFake", "count": 7}],
                        "popular_threat_category": [{"value": "trojan", "count": 7}],
                    },
                    "tags": ["trojan", "downloader"],
                    "sha256": "3515daf08a5daa104a8be3169d64bef2",
                },
            }
        }

        record = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="931",
            value="3515daf08a5daa104a8be3169d64bef2",
            value_type="FileHash-MD5",
            tags=["otx"],
            raw_payload={"id": 931},
        )

        stdout = StringIO()
        call_command(
            "import_virustotal",
            limit=1,
            throttle_seconds=0,
            stdout=stdout,
        )

        record.refresh_from_db()
        self.assertIn("virustotal", record.enrichment_payloads)
        self.assertEqual(record.malware_family, "ClearFake")
        self.assertEqual(record.threat_type, "trojan")
        self.assertEqual(record.confidence_level, 65)
        self.assertEqual(
            record.reference_url,
            "https://www.virustotal.com/api/v3/files/3515daf08a5daa104a8be3169d64bef2",
        )
        self.assertEqual(record.tags, ["otx", "trojan", "downloader"])
        provider_run = ProviderRun.objects.get(provider_name="virustotal")
        self.assertEqual(provider_run.run_type, ProviderRun.RunType.ENRICHMENT)
        self.assertEqual(provider_run.status, ProviderRun.Status.SUCCESS)
        self.assertEqual(provider_run.records_fetched, 1)
        self.assertEqual(provider_run.records_updated, 1)
        self.assertIn("VirusTotal enrichment complete", stdout.getvalue())
        self.assertIn("Starting VirusTotal enrichment", stdout.getvalue())
        self.assertIn("[1/1] Enriched IOC", stdout.getvalue())
        mock_throttle.assert_not_called()

    def test_detail_context_exposes_virustotal_enrichment_sections(self):
        enrichment = build_virustotal_enrichment(
            "clearfake.example",
            "domain",
            {
                "data": {
                    "id": "clearfake.example",
                    "type": "domain",
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/domains/clearfake.example"
                    },
                    "attributes": {
                        "categories": {"Forcepoint": "malware"},
                        "last_analysis_stats": {
                            "harmless": 1,
                            "malicious": 9,
                            "suspicious": 0,
                            "undetected": 0,
                        },
                        "tags": ["malware", "phishing"],
                        "whois": "Registrar: Example",
                    },
                }
            },
        )
        record = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="otx-domain-1",
            value="clearfake.example",
            value_type="domain",
            enrichment_payloads={"virustotal": enrichment},
            confidence_level=90,
        )

        context = build_detail_context(record)

        self.assertIsNotNone(context["virustotal_context"])
        self.assertEqual(
            context["virustotal_context"]["analysis_items"][1]["value"],
            "9/10",
        )
        self.assertEqual(
            context["virustotal_context"]["artifact_items"][0]["label"],
            "Domain",
        )
        self.assertIn(
            "\"categories\": {",
            context["virustotal_context"]["raw_pretty"],
        )

    def test_confidence_distribution_includes_virustotal_scored_alienvault_rows(self):
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="otx-null-1",
            value="hash-null-1",
            value_type="FileHash-MD5",
            confidence_level=None,
        )
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="otx-vt-1",
            value="hash-scored-1",
            value_type="FileHash-MD5",
            confidence_level=82,
            enrichment_payloads={"virustotal": {"summary": {"analysis_score": 82}}},
        )

        context = build_dashboard_context(
            DashboardFilters(
                start_date=None,
                end_date=None,
                value_type="",
                malware_family="",
                threat_type="",
                confidence_band="",
                search="",
                tag="",
                page=1,
                page_size=25,
            )
        )

        distribution = dict(
            zip(
                context["confidence_distribution"]["labels"],
                context["confidence_distribution"]["values"],
            )
        )
        self.assertEqual(distribution["Unknown"], 0)
        self.assertEqual(distribution["75-100"], 1)


class DetailViewRenderingTests(TestCase):
    def setUp(self):
        self.large_payload_record = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="detail-large-1",
            value="fd4b54bb92dd5c8cd056da618894816a",
            value_type="FileHash-MD5",
            threat_type="MALWARE",
            confidence_level=76,
            raw_payload={
                "id": 926,
                "indicator": "fd4b54bb92dd5c8cd056da618894816a",
                "type": "FileHash-MD5",
                "description": "Large payload rendering validation",
                "content": "\n".join(
                    f"payload-line-{index:04d}: long forensic narrative"
                    for index in range(300)
                ),
            },
            last_ingested_at=datetime(2026, 4, 11, 13, 48, tzinfo=timezone.utc),
        )
        self.minimal_record = IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="detail-minimal-1",
            value="minimal-example.test",
            value_type="domain",
            raw_payload={},
        )

    def test_dashboard_view_loads_with_mixed_payload_sizes(self):
        response = self.client.get(reverse("intel:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intel/dashboard.html")
        self.assertContains(response, "fd4b54bb92dd5c8cd056da618894816a")
        self.assertContains(response, "minimal-example.test")

    def test_ioc_detail_view_uses_bounded_payload_shell_for_large_payload(self):
        response = self.client.get(
            reverse("intel:ioc_detail", args=[self.large_payload_record.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intel/ioc_detail.html")
        self.assertContains(response, "payload-scroll-shell")
        self.assertContains(response, "code-block-scroll")
        self.assertContains(response, "payload-line-0000")
        self.assertIn("payload-line-0299", response.context["raw_payload_pretty"])

    def test_ioc_detail_view_handles_empty_payload_without_layout_failure(self):
        response = self.client.get(
            reverse("intel:ioc_detail", args=[self.minimal_record.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intel/ioc_detail.html")
        self.assertContains(response, "payload-scroll-shell")
        self.assertContains(response, "{}")

    def test_ioc_blade_detail_view_returns_200_for_seeded_ioc(self):
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="detail-blade-1",
            value="59.153.164.91",
            value_type="ip",
            enrichment_payloads={
                "virustotal": {
                    "summary": {
                        "object_id": "59.153.164.91",
                        "reference_url": "https://virustotal.example/ip/59.153.164.91",
                        "analysis_score": 88,
                    }
                }
            },
        )

        response = self.client.get(
            reverse("intel:ioc_blade_detail"),
            {"value": "59.153.164.91", "value_type": "ip"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "intel/ioc_blade_detail.html")
        self.assertContains(response, "Platform Coverage")


class DashboardSortingAndLinkRenderingTests(TestCase):
    def setUp(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="sort-a",
            value="alpha.example",
            value_type="domain",
            confidence_level=15,
            reference_url="https://threatfox.abuse.ch/ioc/910001/",
            external_references=[
                {
                    "provider": "threatfox",
                    "label": "ThreatFox record",
                    "url": "https://threatfox.abuse.ch/ioc/910001/",
                }
            ],
            last_ingested_at=datetime(2026, 4, 9, 10, 0, tzinfo=timezone.utc),
        )
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="sort-b",
            value="zulu.example",
            value_type="domain",
            confidence_level=95,
            external_references=[],
            enrichment_payloads={
                "virustotal": {
                    "summary": {
                        "object_type": "domain",
                        "object_id": "zulu.example",
                        "analysis_score": 95,
                    }
                }
            },
            last_ingested_at=datetime(2026, 4, 11, 10, 0, tzinfo=timezone.utc),
        )
        IntelIOC.objects.create(
            source_name="urlhaus",
            source_record_id="sort-c",
            value="https://cdn.bad-download.example/payload.zip",
            value_type="url",
            confidence_level=None,
            reference_url="https://urlhaus.abuse.ch/url/910003/",
            external_references=[
                {
                    "provider": "urlhaus",
                    "label": "URLhaus URL record",
                    "url": "https://urlhaus.abuse.ch/url/910003/",
                }
            ],
            last_ingested_at=datetime(2026, 4, 10, 10, 0, tzinfo=timezone.utc),
        )

    def test_dashboard_sorting_by_value_ascending_is_stable(self):
        response = self.client.get(
            reverse("intel:dashboard"),
            {"sort": "value", "direction": "asc"},
        )

        self.assertEqual(response.status_code, 200)
        values = [row["record"].value for row in response.context["recent_ioc_rows"]]
        self.assertEqual(values[:3], ["alpha.example", "https://cdn.bad-download.example/payload.zip", "zulu.example"])

    def test_dashboard_sorting_by_confidence_descending_prioritizes_scored_records(self):
        response = self.client.get(
            reverse("intel:dashboard"),
            {"sort": "confidence", "direction": "desc"},
        )

        self.assertEqual(response.status_code, 200)
        values = [row["record"].value for row in response.context["recent_ioc_rows"]]
        self.assertEqual(values[0], "zulu.example")
        self.assertEqual(response.context["sort_state"]["sort_by"], "confidence")
        self.assertEqual(response.context["sort_state"]["direction"], "desc")

    def test_dashboard_source_links_render_real_labels_and_no_dummy_reference_anchor(self):
        response = self.client.get(reverse("intel:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "ThreatFox record")
        self.assertContains(response, "URLhaus URL record")
        self.assertNotContains(response, ">Reference<", html=False)

    def test_detail_view_renders_virustotal_auth_note_honestly(self):
        record = IntelIOC.objects.get(source_record_id="sort-b")

        response = self.client.get(reverse("intel:ioc_detail", args=[record.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "May require a VirusTotal sign-in for full context.")


class PopulateSampleIocsCommandTests(TestCase):
    def test_populate_sample_iocs_creates_expected_records(self):
        stdout = StringIO()

        call_command("populate_sample_iocs", stdout=stdout)

        self.assertIn("Sample IOC population complete", stdout.getvalue())
        self.assertEqual(IntelIOC.objects.count(), 6)

        normal_record = IntelIOC.objects.get(source_record_id="sample-threatfox-ip-1")
        large_payload_record = IntelIOC.objects.get(source_record_id="sample-alienvault-ip-1")
        url_record = IntelIOC.objects.get(source_record_id="sample-urlhaus-url-1")
        hash_record = IntelIOC.objects.get(source_record_id="sample-alienvault-hash-1")
        minimal_record = IntelIOC.objects.get(source_record_id="sample-minimal-domain-1")

        self.assertEqual(normal_record.value, "59.153.164.91")
        self.assertGreater(len(large_payload_record.raw_payload["content"]), 10000)
        self.assertEqual(url_record.value_type, "url")
        self.assertEqual(hash_record.value_type, "FileHash-MD5")
        self.assertEqual(minimal_record.raw_payload, {})

    def test_populate_sample_iocs_is_idempotent_and_dashboard_search_sees_sources(self):
        call_command("populate_sample_iocs")
        call_command("populate_sample_iocs")

        self.assertEqual(IntelIOC.objects.count(), 6)

        response = self.client.get(
            reverse("intel:dashboard"),
            {"search": "59.153.164.91"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Aggregated IOC Blades")
        self.assertContains(response, "ThreatFox")
        self.assertContains(response, "AlienVault")
        self.assertContains(response, "VirusTotal")

    def test_sample_ioc_payloads_cover_multiple_ioc_types_and_payload_shapes(self):
        payloads = sample_ioc_payloads()

        self.assertEqual(len(payloads), 6)
        self.assertEqual(payloads[0]["value"], "59.153.164.91")
        self.assertGreater(len(payloads[1]["raw_payload"]["content"]), 10000)
        self.assertEqual(payloads[2]["value_type"], "domain")
        self.assertEqual(payloads[3]["value_type"], "url")
        self.assertEqual(payloads[4]["value_type"], "FileHash-MD5")
        self.assertEqual(payloads[5]["raw_payload"], {})


class TimeDisplayPreferenceTests(TestCase):
    def test_set_time_display_saves_selection_in_session(self):
        response = self.client.post(
            reverse("intel:set_time_display"),
            {"time_display_option": "utc_24", "next": reverse("intel:dashboard")},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("intel:dashboard"))
        self.assertEqual(self.client.session[TIME_DISPLAY_SESSION_KEY], "utc_24")

    def test_dashboard_renders_utc_suffix_when_utc_option_selected(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="time-format-1",
            value="time-format.example",
            value_type="domain",
            first_seen=datetime(2026, 4, 10, 1, 0, tzinfo=timezone.utc),
            last_seen=datetime(2026, 4, 11, 5, 30, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 11, 6, 0, tzinfo=timezone.utc),
        )
        session = self.client.session
        session[TIME_DISPLAY_SESSION_KEY] = "utc_24"
        session.save()

        response = self.client.get(reverse("intel:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "UTC")

    @override_settings(INTEL_LOCAL_TIME_ZONE="America/New_York")
    def test_dashboard_renders_local_time_in_eastern_timezone(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="time-format-2",
            value="eastern-time.example",
            value_type="domain",
            first_seen=datetime(2026, 4, 11, 23, 0, tzinfo=timezone.utc),
            last_seen=datetime(2026, 4, 11, 23, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 11, 23, 0, tzinfo=timezone.utc),
        )
        session = self.client.session
        session[TIME_DISPLAY_SESSION_KEY] = "friendly_local_12"
        session.save()

        response = self.client.get(reverse("intel:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Apr 11, 2026 7:00 PM")
