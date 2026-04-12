from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase

from intel.models import IntelIOC


class TrimIocSamplesCommandTests(TestCase):
    def _create_ioc(self, record_id: str, *, first_seen=None, last_ingested_at=None):
        ioc = IntelIOC.objects.create(
            source_name="threatfox",
            source_record_id=record_id,
            value=f"{record_id}.example",
            value_type="domain",
            first_seen=first_seen,
        )
        if last_ingested_at is not None:
            IntelIOC.objects.filter(pk=ioc.pk).update(last_ingested_at=last_ingested_at)
            ioc.refresh_from_db()
        return ioc

    def _create_rows(self, count: int):
        for index in range(count):
            IntelIOC.objects.create(
                source_name="threatfox",
                source_record_id=f"bulk-{index}",
                value=f"bulk-{index}.example",
                value_type="domain",
            )

    @patch("intel.services.refresh_pipeline.refresh_dashboard_snapshot")
    def test_trim_newest_1000_when_table_exceeds_limit(self, mock_snapshot):
        self._create_rows(1005)
        mock_snapshot.return_value = {
            "result_count": 1000,
            "has_data": True,
            "newest_ingest": "2026-04-12T12:00:00+00:00",
        }
        stdout = StringIO()

        call_command("trim_ioc_samples", stdout=stdout)
        output = stdout.getvalue()

        self.assertEqual(IntelIOC.objects.count(), 1000)
        self.assertIn("before_count: 1005", output)
        self.assertIn("deleted_count: 5", output)
        self.assertIn("retained_count: 1000", output)
        self.assertIn("after_count: 1000", output)
        mock_snapshot.assert_called_once()

    def test_trim_noop_when_table_exactly_1000(self):
        self._create_rows(1000)
        stdout = StringIO()

        call_command("trim_ioc_samples", stdout=stdout)
        output = stdout.getvalue()

        self.assertEqual(IntelIOC.objects.count(), 1000)
        self.assertIn("before_count: 1000", output)
        self.assertIn("deleted_count: 0", output)
        self.assertIn("retained_count: 1000", output)
        self.assertIn("after_count: 1000", output)

    def test_trim_noop_when_table_below_1000(self):
        self._create_rows(999)
        stdout = StringIO()

        call_command("trim_ioc_samples", stdout=stdout)
        output = stdout.getvalue()

        self.assertEqual(IntelIOC.objects.count(), 999)
        self.assertIn("before_count: 999", output)
        self.assertIn("deleted_count: 0", output)
        self.assertIn("retained_count: 999", output)
        self.assertIn("after_count: 999", output)

    def test_trim_dry_run_does_not_delete_rows(self):
        self._create_rows(1005)
        stdout = StringIO()

        call_command("trim_ioc_samples", dry_run=True, stdout=stdout)
        output = stdout.getvalue()

        self.assertEqual(IntelIOC.objects.count(), 1005)
        self.assertIn("status: dry_run", output)
        self.assertIn("before_count: 1005", output)
        self.assertIn("deleted_count: 5", output)
        self.assertIn("retained_count: 1000", output)
        self.assertIn("after_count: 1005", output)

    @patch("intel.services.refresh_pipeline.refresh_dashboard_snapshot")
    def test_trim_respects_custom_limit(self, mock_snapshot):
        self._create_rows(120)
        mock_snapshot.return_value = {
            "result_count": 50,
            "has_data": True,
            "newest_ingest": "2026-04-12T12:00:00+00:00",
        }

        call_command("trim_ioc_samples", limit=50)

        self.assertEqual(IntelIOC.objects.count(), 50)
        mock_snapshot.assert_called_once()

    def test_trim_orders_by_last_ingested_not_first_seen(self):
        now = datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc)
        old_by_ingest = self._create_ioc(
            "ordering-old-ingest",
            first_seen=now + timedelta(days=10),
            last_ingested_at=now - timedelta(days=10),
        )
        keep_a = self._create_ioc(
            "ordering-keep-a",
            first_seen=now - timedelta(days=10),
            last_ingested_at=now - timedelta(minutes=2),
        )
        keep_b = self._create_ioc(
            "ordering-keep-b",
            first_seen=now - timedelta(days=9),
            last_ingested_at=now - timedelta(minutes=1),
        )

        call_command("trim_ioc_samples", limit=2)

        self.assertFalse(IntelIOC.objects.filter(pk=old_by_ingest.pk).exists())
        self.assertTrue(IntelIOC.objects.filter(pk=keep_a.pk).exists())
        self.assertTrue(IntelIOC.objects.filter(pk=keep_b.pk).exists())
