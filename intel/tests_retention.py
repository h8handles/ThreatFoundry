from datetime import datetime, timezone
from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from intel.models import IntelIOC
from intel.services.retention import cleanup_old_iocs


class RetentionServiceTests(TestCase):
    def _create_ioc(self, *, record_id: str, first_seen=None, last_ingested_at=None):
        ioc = IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id=record_id,
            value=f"{record_id}.example",
            value_type="domain",
            first_seen=first_seen,
        )
        effective_last_ingested_at = last_ingested_at or first_seen
        if effective_last_ingested_at is not None:
            IntelIOC.objects.filter(pk=ioc.pk).update(last_ingested_at=effective_last_ingested_at)
            ioc.refresh_from_db()
        return ioc

    def test_cleanup_skips_when_dataset_younger_than_seven_days(self):
        now = datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc)
        self._create_ioc(
            record_id="young-1",
            first_seen=datetime(2026, 4, 6, 12, 0, tzinfo=timezone.utc),
        )
        self._create_ioc(
            record_id="young-2",
            first_seen=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
        )

        result = cleanup_old_iocs(dry_run=False, now=now)

        self.assertEqual(result.status, "warmup")
        self.assertEqual(IntelIOC.objects.count(), 2)

    def test_cleanup_deletes_rows_older_than_three_days_after_warmup(self):
        self._create_ioc(
            record_id="old-delete",
            first_seen=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
        )
        self._create_ioc(
            record_id="keep-1",
            first_seen=datetime(2026, 4, 9, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 9, 12, 0, tzinfo=timezone.utc),
        )
        self._create_ioc(
            record_id="keep-2",
            first_seen=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
        )
        now = datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc)
        result = cleanup_old_iocs(dry_run=False, now=now)

        self.assertEqual(result.status, "deleted")
        self.assertFalse(IntelIOC.objects.filter(source_record_id="old-delete").exists())
        self.assertTrue(IntelIOC.objects.filter(source_record_id="keep-1").exists())
        self.assertTrue(IntelIOC.objects.filter(source_record_id="keep-2").exists())

    def test_cleanup_uses_last_ingested_when_first_seen_missing(self):
        self._create_ioc(
            record_id="fallback-old",
            first_seen=None,
            last_ingested_at=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
        )
        self._create_ioc(
            record_id="fallback-keep",
            first_seen=None,
            last_ingested_at=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
        )
        now = datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc)
        result = cleanup_old_iocs(dry_run=False, now=now)

        self.assertEqual(result.status, "deleted")
        self.assertFalse(IntelIOC.objects.filter(source_record_id="fallback-old").exists())
        self.assertTrue(IntelIOC.objects.filter(source_record_id="fallback-keep").exists())

    def test_cleanup_keeps_recently_reingested_rows_even_with_old_first_seen(self):
        self._create_ioc(
            record_id="reingested-keep",
            first_seen=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
        )
        self._create_ioc(
            record_id="old-delete",
            first_seen=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
        )
        now = datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc)
        result = cleanup_old_iocs(dry_run=False, now=now)

        self.assertEqual(result.status, "deleted")
        self.assertTrue(IntelIOC.objects.filter(source_record_id="reingested-keep").exists())
        self.assertFalse(IntelIOC.objects.filter(source_record_id="old-delete").exists())

    def test_cleanup_dry_run_reports_deletions_but_keeps_rows(self):
        self._create_ioc(
            record_id="dry-old",
            first_seen=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
        )
        self._create_ioc(
            record_id="dry-keep",
            first_seen=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 10, 12, 0, tzinfo=timezone.utc),
        )
        now = datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc)
        result = cleanup_old_iocs(dry_run=True, now=now)

        self.assertEqual(result.status, "dry_run")
        self.assertEqual(result.total_deleted, 1)
        self.assertEqual(IntelIOC.objects.count(), 2)

    def test_cleanup_safety_stop_prevents_full_table_wipe(self):
        self._create_ioc(
            record_id="wipe-1",
            first_seen=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc),
        )
        self._create_ioc(
            record_id="wipe-2",
            first_seen=datetime(2026, 4, 2, 12, 0, tzinfo=timezone.utc),
            last_ingested_at=datetime(2026, 4, 2, 12, 0, tzinfo=timezone.utc),
        )
        now = datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc)
        result = cleanup_old_iocs(dry_run=False, now=now)

        self.assertEqual(result.status, "safety_stop")
        self.assertEqual(IntelIOC.objects.count(), 2)


class CleanupOldIocsCommandTests(TestCase):
    def test_command_prints_cleanup_summary(self):
        stdout = StringIO()
        call_command("cleanup_old_iocs", dry_run=True, stdout=stdout)
        output = stdout.getvalue()

        self.assertIn("status:", output)
        self.assertIn("cutoff_timestamp:", output)
        self.assertIn("total_rows_before:", output)
        self.assertIn("total_rows_deleted:", output)
        self.assertIn("total_rows_remaining:", output)
