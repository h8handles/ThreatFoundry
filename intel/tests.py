import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows does not provide fcntl
    fcntl = None

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from config import settings as project_settings
from intel.access import ADMIN_GROUP, ANALYST_GROUP, DEFAULT_GROUPS, VIEWER_GROUP
from intel.models import IngestionRun, IntelIOC, ProviderRun, ProviderRunDetail
from intel.management.commands.populate_sample_iocs import sample_ioc_payloads
from intel.services.correlation import build_hash_correlation_context, canonical_hash_type
from intel.services.correlation import (
    build_correlation_reasons,
    correlate_unknown_iocs,
    normalize_family_alias,
    score_ioc_correlation,
)
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
from intel.services.virustotal import (
    VirusTotalNotFound,
    build_virustotal_enrichment,
    derive_platform_updates,
)
from intel.time_display import TIME_DISPLAY_SESSION_KEY


User = get_user_model()


def create_user_with_group(*, username, group_name, is_staff=False, is_superuser=False):
    user = User.objects.create_user(
        username=username,
        password="test-pass-123",
        is_staff=is_staff,
        is_superuser=is_superuser,
    )
    if group_name:
        user.groups.add(Group.objects.get(name=group_name))
    return user


class ViewerAccessTestCase(TestCase):
    def setUp(self):
        super().setUp()
        self.viewer_user = create_user_with_group(
            username="viewer-user",
            group_name=VIEWER_GROUP,
        )
        self.client.force_login(self.viewer_user)


class AnalystAccessTestCase(TestCase):
    def setUp(self):
        super().setUp()
        self.analyst_user = create_user_with_group(
            username="analyst-user",
            group_name=ANALYST_GROUP,
        )
        self.client.force_login(self.analyst_user)


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


class CorrelationEngineTests(TestCase):
    def test_normalize_family_alias_collapses_common_variants(self):
        self.assertEqual(normalize_family_alias("Clear Fake"), "clearfake")
        self.assertEqual(normalize_family_alias("Async_RAT"), "asyncrat")

    def test_correlate_unknown_iocs_promotes_when_local_signals_are_strong(self):
        now = datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc)
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="corr-known-1",
            value="shared.example",
            value_type="domain",
            threat_type="phishing",
            malware_family="ClearFake",
            confidence_level=85,
            tags=["phishing", "clearfake"],
            reporter="abuse_ch",
            last_seen=now,
        )
        IntelIOC.objects.create(
            source_name="urlhaus",
            source_record_id="corr-known-2",
            value="https://shared.example/payload/dropper.zip",
            value_type="url",
            threat_type="malware_download",
            malware_family="ClearFake",
            tags=["clearfake", "payload"],
            reporter="abuse_ch",
            raw_payload={"signature": "ClearFake"},
            last_seen=now - timedelta(days=1),
            enrichment_payloads={
                "virustotal": {
                    "summary": {
                        "popular_threat_names": [{"label": "ClearFake", "count": 3}],
                        "popular_threat_categories": [{"label": "phishing", "count": 2}],
                    }
                }
            },
        )
        unknown = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="corr-unknown-1",
            value="shared.example",
            value_type="domain",
            threat_type="Unknown",
            malware_family="",
            confidence_level=None,
            tags=["clearfake", "phishing"],
            reporter="abuse_ch",
            last_seen=now - timedelta(days=1),
            enrichment_payloads={
                "virustotal": {
                    "summary": {
                        "popular_threat_names": [{"label": "ClearFake", "count": 4}],
                        "popular_threat_categories": [{"label": "phishing", "count": 2}],
                    }
                }
            },
        )

        result = correlate_unknown_iocs()

        unknown.refresh_from_db()
        self.assertEqual(result["promoted"], 1)
        self.assertGreaterEqual(unknown.derived_confidence_level, 60)
        self.assertEqual(unknown.likely_malware_family, "ClearFake")
        self.assertEqual(unknown.likely_threat_type, "phishing")
        self.assertTrue(unknown.correlation_reasons)

    def test_correlate_unknown_iocs_keeps_low_score_records_unknown(self):
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="corr-low-1",
            value="other.example",
            value_type="domain",
            threat_type="credential_theft",
            malware_family="AsyncRAT",
            confidence_level=70,
            tags=["rat"],
        )
        unknown = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="corr-low-2",
            value="loose.example",
            value_type="domain",
            threat_type="",
            malware_family="",
            confidence_level=None,
            tags=["misc"],
        )

        result = correlate_unknown_iocs()

        unknown.refresh_from_db()
        self.assertEqual(result["skipped"], 1)
        self.assertIsNone(unknown.derived_confidence_level)
        self.assertEqual(unknown.likely_malware_family, "")
        self.assertEqual(unknown.likely_threat_type, "")
        self.assertIn("No sufficiently strong local correlation signals were found.", unknown.correlation_reasons)

    def test_score_and_reasons_reflect_exact_multisource_match(self):
        known = IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="corr-score-1",
            value="score.example",
            value_type="domain",
            threat_type="phishing",
            malware_family="ClearFake",
            tags=["clearfake"],
            last_seen=datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc),
        )
        record = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="corr-score-2",
            value="score.example",
            value_type="domain",
            threat_type="",
            malware_family="",
            confidence_level=None,
            tags=["clearfake"],
            last_seen=datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
        )

        score = score_ioc_correlation(record, [known])
        reasons = build_correlation_reasons(record, [known])

        self.assertGreaterEqual(score, 45)
        self.assertTrue(any("Exact IOC value/type match" in reason for reason in reasons))


class SettingsParsingTests(SimpleTestCase):
    def test_build_allowed_hosts_defaults_to_wildcard_in_debug(self):
        self.assertEqual(
            project_settings._build_allowed_hosts(
                "",
                debug=True,
                runserver_host="172.30.150.130",
            ),
            ["*"],
        )

    def test_build_allowed_hosts_uses_explicit_csv_values(self):
        self.assertEqual(
            project_settings._build_allowed_hosts(
                "localhost, 127.0.0.1 , threatfoundry.local",
                debug=True,
                runserver_host="172.30.150.130",
            ),
            ["localhost", "127.0.0.1", "threatfoundry.local"],
        )

    def test_build_csrf_trusted_origins_uses_default_dev_origins(self):
        self.assertEqual(
            project_settings._build_csrf_trusted_origins(
                "",
                runserver_host="172.30.150.130",
                runserver_port="8080",
            ),
            [
                "http://localhost:8080",
                "http://127.0.0.1:8080",
                "http://172.30.150.130:8080",
            ],
        )


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

    @override_settings(
        INTEL_REFRESH_VIRUSTOTAL_LIMIT=10,
        INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS=0,
    )
    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-vt-key"}, clear=False)
    @patch("intel.services.virustotal.fetch_virustotal_report")
    def test_refresh_intel_prints_virustotal_skip_diagnostics(
        self,
        mock_fetch_virustotal_report,
    ):
        unsupported = IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="tf-email-1",
            value="operator@example.test",
            value_type="email",
        )
        missing = IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="otx-domain-1",
            value="missing.example",
            value_type="domain",
        )

        def fake_fetch(value, value_type, timeout=30):
            raise VirusTotalNotFound(
                f"VirusTotal has no report for {value_type} {value}."
            )

        mock_fetch_virustotal_report.side_effect = fake_fetch

        stdout = StringIO()
        call_command(
            "refresh_intel",
            provider="virustotal",
            no_feed_refresh=True,
            stdout=stdout,
        )

        output = stdout.getvalue()
        self.assertIn(
            "virustotal: skipped (fetched=2, created=0, updated=0, skipped=2)",
            output,
        )
        self.assertIn(
            "skip breakdown: already enriched=0, unsupported lookup type=0, VT not found=2, no changes after enrichment=0, error=0",
            output,
        )
        self.assertIn(
            f"IOC {unsupported.pk} value=operator@example.test type=email already_enriched=False lookup=unsupported db_changed=no reason=not_found",
            output,
        )
        self.assertIn(
            f"IOC {missing.pk} value=missing.example type=domain already_enriched=False lookup=supported db_changed=no reason=not_found",
            output,
        )

        detail = ProviderRunDetail.objects.get(provider_name="virustotal")
        self.assertEqual(
            detail.details["skip_breakdown"],
            {
                "already_enriched": 0,
                "unsupported_lookup_type": 0,
                "not_found": 2,
                "no_changes_after_enrichment": 0,
                "error": 0,
            },
        )
        self.assertEqual(len(detail.details["record_diagnostics"]), 2)

    @patch.dict("os.environ", {"THREATFOX_API_KEY": "test-threatfox-key"}, clear=False)
    @patch("intel.services.refresh_pipeline.fetch_threatfox_iocs")
    def test_refresh_intel_scheduled_logs_to_file_and_marks_run_scheduled(
        self,
        mock_threatfox,
    ):
        mock_threatfox.return_value = {
            "data": [
                {
                    "id": "tf-1",
                    "ioc": "scheduled.example",
                    "ioc_type": "domain",
                }
            ]
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "refresh.log"
            lock_file = Path(tmp_dir) / "refresh.lock"

            stdout = StringIO()
            call_command(
                "refresh_intel_scheduled",
                provider="threatfox",
                log_file=str(log_file),
                lock_file=str(lock_file),
                no_feed_refresh=True,
                stdout=stdout,
            )

            run = IngestionRun.objects.get()
            self.assertEqual(run.trigger, "scheduled")
            self.assertEqual(run.status, IngestionRun.Status.SUCCESS)
            log_text = log_file.read_text()
            self.assertIn("scheduled refresh starting", log_text)
            self.assertIn("threatfox: success", log_text)
            self.assertIn("scheduled refresh finished successfully", log_text)
            self.assertIn("refresh_intel complete", stdout.getvalue())

    @patch.dict("os.environ", {"THREATFOX_API_KEY": "test-threatfox-key"}, clear=False)
    @patch("intel.services.refresh_pipeline.fetch_threatfox_iocs")
    @unittest.skipIf(fcntl is None, "fcntl is not available on this platform.")
    def test_refresh_intel_scheduled_skips_when_lock_is_held(
        self,
        mock_threatfox,
    ):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "refresh.log"
            lock_file = Path(tmp_dir) / "refresh.lock"

            lock_file.parent.mkdir(parents=True, exist_ok=True)
            with lock_file.open("a+", encoding="utf-8") as held_lock:
                held_lock.write("pid=999 started_at=2026-04-12T01:00:00+00:00")
                held_lock.flush()
                fcntl.flock(held_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                stdout = StringIO()
                call_command(
                    "refresh_intel_scheduled",
                    provider="threatfox",
                    log_file=str(log_file),
                    lock_file=str(lock_file),
                    stdout=stdout,
                )

            self.assertFalse(mock_threatfox.called)
            self.assertEqual(IngestionRun.objects.count(), 0)
            log_text = log_file.read_text()
            self.assertIn("scheduled refresh skipped; another run holds", log_text)
            self.assertIn("pid=999", log_text)
            self.assertIn("scheduled refresh skipped; another run holds", stdout.getvalue())


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


class AlienVaultPresentationTests(ViewerAccessTestCase):
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


class DetailViewRenderingTests(ViewerAccessTestCase):
    def setUp(self):
        super().setUp()
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

    @patch("intel.views.lookup_whois_target")
    def test_ioc_detail_view_renders_whois_blade_for_supported_ioc_types(self, mock_lookup):
        mock_lookup.return_value = {
            "ok": True,
            "result": {
                "target": "minimal-example.test",
                "target_type": "domain",
                "registered_domain": "example.test",
                "resolved_ip": "203.0.113.10",
                "whois": {
                    "registrar": "Example Registrar",
                    "organization": "Example Org",
                    "creation_date": "2024-01-01",
                    "expiration_date": "2027-01-01",
                    "updated_date": "2026-01-01",
                },
                "geolocation": {
                    "country": "United States",
                    "city": "New York",
                    "region": "New York",
                    "isp": "Example ISP",
                    "asn": "AS64496",
                },
            },
        }

        response = self.client.get(
            reverse("intel:ioc_detail", args=[self.minimal_record.pk])
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "WHOIS &amp; Geolocation")
        self.assertContains(response, "Summary")
        self.assertContains(response, "WHOIS")
        self.assertContains(response, "Geolocation")
        self.assertContains(response, "Example Registrar")
        self.assertContains(response, "United States")

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


class DashboardSortingAndLinkRenderingTests(ViewerAccessTestCase):
    def setUp(self):
        super().setUp()
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

    def test_dashboard_hunt_controls_export_link_keeps_scope_query(self):
        response = self.client.get(
            reverse("intel:dashboard"),
            {"search": "alpha.example", "value_type": "domain", "tag": "phishing"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("intel:dashboard_export_csv"))
        self.assertContains(response, "search=alpha.example")
        self.assertContains(response, "value_type=domain")
        self.assertContains(response, "tag=phishing")

    def test_dashboard_export_csv_honors_filter_scope(self):
        response = self.client.get(
            reverse("intel:dashboard_export_csv"),
            {"search": "alpha.example"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn("attachment; filename=", response["Content-Disposition"])

        csv_body = "".join(
            chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
            for chunk in response.streaming_content
        )
        self.assertIn("alpha.example", csv_body)
        self.assertNotIn("zulu.example", csv_body)


class PopulateSampleIocsCommandTests(ViewerAccessTestCase):
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


class TimeDisplayPreferenceTests(ViewerAccessTestCase):
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


class AuthenticationAndAccessControlTests(TestCase):
    def setUp(self):
        self.record = IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="auth-1",
            value="auth.example",
            value_type="domain",
        )
        self.viewer_user = create_user_with_group(
            username="viewer-auth",
            group_name=VIEWER_GROUP,
        )
        self.analyst_user = create_user_with_group(
            username="analyst-auth",
            group_name=ANALYST_GROUP,
        )
        self.admin_user = create_user_with_group(
            username="admin-auth",
            group_name=ADMIN_GROUP,
            is_staff=True,
        )

    def test_default_groups_exist(self):
        self.assertEqual(
            set(Group.objects.filter(name__in=DEFAULT_GROUPS).values_list("name", flat=True)),
            set(DEFAULT_GROUPS),
        )

    def test_protected_html_routes_redirect_anonymous_users_to_login(self):
        route_specs = [
            reverse("intel:dashboard"),
            reverse("intel:documentation"),
            reverse("intel:malware_family"),
            reverse("intel:ioc_detail", args=[self.record.pk]),
        ]

        for route in route_specs:
            with self.subTest(route=route):
                response = self.client.get(route)
                self.assertEqual(response.status_code, 302)
                self.assertIn(reverse("login"), response["Location"])

    def test_login_and_logout_flow_redirects_cleanly(self):
        login_response = self.client.post(
            reverse("login"),
            {"username": "viewer-auth", "password": "test-pass-123"},
        )
        self.assertRedirects(login_response, reverse("intel:dashboard"))

        logout_response = self.client.post(reverse("logout"))
        self.assertRedirects(logout_response, reverse("login"))

    def test_register_flow_creates_user_assigns_viewer_group_and_logs_in(self):
        response = self.client.post(
            reverse("register"),
            {
                "username": "new-viewer",
                "password1": "StrongTestPass123!",
                "password2": "StrongTestPass123!",
            },
        )

        self.assertRedirects(response, reverse("intel:dashboard"))
        created_user = User.objects.get(username="new-viewer")
        self.assertTrue(created_user.groups.filter(name=VIEWER_GROUP).exists())

        dashboard_response = self.client.get(reverse("intel:dashboard"))
        self.assertEqual(dashboard_response.status_code, 200)

    def test_viewer_can_access_dashboard_but_not_analyst_chat(self):
        self.client.force_login(self.viewer_user)

        dashboard_response = self.client.get(reverse("intel:dashboard"))
        chat_response = self.client.get(reverse("intel:analyst_chat"))

        self.assertEqual(dashboard_response.status_code, 200)
        self.assertEqual(chat_response.status_code, 403)

    def test_analyst_and_admin_can_access_analyst_chat(self):
        for user in (self.analyst_user, self.admin_user):
            with self.subTest(user=user.username):
                self.client.force_login(user)
                response = self.client.get(reverse("intel:analyst_chat"))
                self.assertEqual(response.status_code, 200)

    def test_assistant_api_requires_authenticated_analyst_role(self):
        anonymous_response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps({"prompt": "test prompt"}),
            content_type="application/json",
        )
        self.assertEqual(anonymous_response.status_code, 401)

        self.client.force_login(self.viewer_user)
        viewer_response = self.client.post(
            reverse("intel:analyst_chat_api"),
            data=json.dumps({"prompt": "test prompt"}),
            content_type="application/json",
        )
        self.assertEqual(viewer_response.status_code, 403)

        self.client.force_login(self.analyst_user)
        with patch("intel.views_chat.build_chat_response") as mock_build_chat_response:
            mock_build_chat_response.return_value = {"answer": "ok"}
            analyst_response = self.client.post(
                reverse("intel:analyst_chat_api"),
                data=json.dumps({"prompt": "test prompt"}),
                content_type="application/json",
            )

        self.assertEqual(analyst_response.status_code, 200)
        self.assertJSONEqual(
            analyst_response.content,
            {"ok": True, "response": {"answer": "ok"}},
        )


class CorrelationCommandAndDashboardTests(ViewerAccessTestCase):
    def test_correlate_unknowns_command_reports_promotions(self):
        now = datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc)
        IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id="cmd-known-1",
            value="cmd.example",
            value_type="domain",
            threat_type="phishing",
            malware_family="ClearFake",
            confidence_level=90,
            tags=["clearfake", "phishing"],
            reporter="abuse_ch",
            last_seen=now,
        )
        IntelIOC.objects.create(
            source_name="urlhaus",
            source_record_id="cmd-known-2",
            value="https://cmd.example/dropper.bin",
            value_type="url",
            threat_type="malware_download",
            malware_family="ClearFake",
            confidence_level=65,
            tags=["clearfake"],
            reporter="abuse_ch",
            raw_payload={"signature": "ClearFake"},
            last_seen=now - timedelta(days=1),
        )
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="cmd-unknown-1",
            value="cmd.example",
            value_type="domain",
            threat_type="",
            malware_family="Unknown",
            confidence_level=None,
            tags=["clearfake"],
            reporter="abuse_ch",
            last_seen=now - timedelta(days=1),
        )

        stdout = StringIO()
        call_command("correlate_unknowns", stdout=stdout)
        output = stdout.getvalue()

        self.assertIn("promoted_count: 1", output)
        self.assertIn("score=", output)

    def test_dashboard_prefers_derived_confidence_for_distribution_and_summary(self):
        IntelIOC.objects.create(
            source_name="alienvault",
            source_record_id="dash-derived-1",
            value="derived.example",
            value_type="domain",
            threat_type="Unknown",
            malware_family="",
            confidence_level=None,
            derived_confidence_level=78,
            likely_malware_family="ClearFake",
            likely_threat_type="phishing",
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
        self.assertEqual(distribution["75-100"], 1)
        self.assertEqual(distribution["Unknown"], 0)
        self.assertEqual(context["kpis"]["average_confidence"], 78)
        self.assertEqual(context["malware_clusters"][0]["label"], "ClearFake")
