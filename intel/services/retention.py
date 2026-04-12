from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from django.db import connection, transaction
from django.db.models import Min
from django.db.models.functions import Coalesce
from django.utils import timezone

from intel.models import IntelIOC


@dataclass
class RetentionCleanupResult:
    total_before: int
    total_deleted: int
    total_remaining: int
    cutoff_timestamp: datetime | None
    oldest_timestamp: datetime | None
    status: str
    message: str
    dry_run: bool


@dataclass
class TrimIocResult:
    total_before: int
    total_deleted: int
    total_retained: int
    total_after: int
    limit: int
    dry_run: bool
    status: str
    message: str
    dashboard_snapshot: dict | None
    vacuum_recommended: bool


def cleanup_old_iocs(
    *, dry_run: bool = False, now: datetime | None = None
) -> RetentionCleanupResult:
    """
    Apply IOC retention policy:
    - Do nothing until the dataset is at least 7 days old.
    - Then retain only the most recent 3 days of IOC records.
    """
    now = now or timezone.now()
    warmup_window = timedelta(days=7)
    retention_window = timedelta(days=3)
    cutoff_timestamp = now - retention_window

    total_before = IntelIOC.objects.count()
    if total_before == 0:
        return RetentionCleanupResult(
            total_before=0,
            total_deleted=0,
            total_remaining=0,
            cutoff_timestamp=cutoff_timestamp,
            oldest_timestamp=None,
            status="no_data",
            message="No IOC rows found. Nothing to clean up.",
            dry_run=dry_run,
        )

    # Retention decisions must follow internal refresh recency, not source-observed time.
    timestamp_qs = IntelIOC.objects.annotate(
        effective_timestamp=Coalesce("last_ingested_at", "updated_at", "created_at")
    )
    oldest_timestamp = timestamp_qs.aggregate(oldest=Min("effective_timestamp"))["oldest"]

    if oldest_timestamp is None:
        return RetentionCleanupResult(
            total_before=total_before,
            total_deleted=0,
            total_remaining=total_before,
            cutoff_timestamp=cutoff_timestamp,
            oldest_timestamp=None,
            status="missing_timestamps",
            message="Could not determine IOC timestamps. Cleanup skipped.",
            dry_run=dry_run,
        )

    dataset_age = now - oldest_timestamp
    if dataset_age < warmup_window:
        return RetentionCleanupResult(
            total_before=total_before,
            total_deleted=0,
            total_remaining=total_before,
            cutoff_timestamp=cutoff_timestamp,
            oldest_timestamp=oldest_timestamp,
            status="warmup",
            message=(
                "Dataset age is below 7 days. Cleanup not started yet."
            ),
            dry_run=dry_run,
        )

    delete_qs = timestamp_qs.filter(effective_timestamp__lt=cutoff_timestamp)
    total_deleted = delete_qs.count()
    total_remaining = total_before - total_deleted

    if total_deleted == 0:
        return RetentionCleanupResult(
            total_before=total_before,
            total_deleted=0,
            total_remaining=total_before,
            cutoff_timestamp=cutoff_timestamp,
            oldest_timestamp=oldest_timestamp,
            status="nothing_to_delete",
            message="No IOC rows are older than the retention cutoff.",
            dry_run=dry_run,
        )

    # Safety rail: never perform a full-table delete from this task.
    if total_remaining == 0:
        return RetentionCleanupResult(
            total_before=total_before,
            total_deleted=0,
            total_remaining=total_before,
            cutoff_timestamp=cutoff_timestamp,
            oldest_timestamp=oldest_timestamp,
            status="safety_stop",
            message=(
                "Cleanup aborted to prevent deleting every IOC row. "
                "At least one retained row is required."
            ),
            dry_run=dry_run,
        )

    if dry_run:
        return RetentionCleanupResult(
            total_before=total_before,
            total_deleted=total_deleted,
            total_remaining=total_before,
            cutoff_timestamp=cutoff_timestamp,
            oldest_timestamp=oldest_timestamp,
            status="dry_run",
            message="Dry run complete. No rows were deleted.",
            dry_run=True,
        )

    deleted_count, _ = delete_qs.delete()
    return RetentionCleanupResult(
        total_before=total_before,
        total_deleted=deleted_count,
        total_remaining=IntelIOC.objects.count(),
        cutoff_timestamp=cutoff_timestamp,
        oldest_timestamp=oldest_timestamp,
        status="deleted",
        message="Retention cleanup complete.",
        dry_run=False,
    )


def trim_iocs_to_limit(*, limit: int = 1000, dry_run: bool = False) -> TrimIocResult:
    """
    Keep only the newest `limit` IOC rows by internal ingestion timestamp.

    Ordering is based on `last_ingested_at` (newest first), with `id` as a
    deterministic tie-breaker.
    """
    if limit <= 0:
        raise ValueError("limit must be greater than zero")

    total_before = IntelIOC.objects.count()
    if total_before <= limit:
        return TrimIocResult(
            total_before=total_before,
            total_deleted=0,
            total_retained=total_before,
            total_after=total_before,
            limit=limit,
            dry_run=dry_run,
            status="no_trim_needed",
            message=f"Row count is already within the limit ({limit}).",
            dashboard_snapshot=None,
            vacuum_recommended=False,
        )

    keep_ids = list(
        IntelIOC.objects.order_by("-last_ingested_at", "-id").values_list("id", flat=True)[:limit]
    )
    delete_qs = IntelIOC.objects.exclude(id__in=keep_ids)
    would_delete = delete_qs.count()
    retained = total_before - would_delete

    if dry_run:
        return TrimIocResult(
            total_before=total_before,
            total_deleted=would_delete,
            total_retained=retained,
            total_after=total_before,
            limit=limit,
            dry_run=True,
            status="dry_run",
            message="Dry run complete. No rows were deleted.",
            dashboard_snapshot=None,
            vacuum_recommended=False,
        )

    with transaction.atomic():
        deleted_count, _ = delete_qs.delete()

    total_after = IntelIOC.objects.count()
    dashboard_snapshot = None
    if deleted_count > 0:
        try:
            from intel.services.refresh_pipeline import refresh_dashboard_snapshot

            dashboard_snapshot = refresh_dashboard_snapshot()
        except Exception:
            dashboard_snapshot = None

    vacuum_recommended = (
        connection.vendor == "postgresql" and deleted_count >= 1000
    )

    return TrimIocResult(
        total_before=total_before,
        total_deleted=deleted_count,
        total_retained=retained,
        total_after=total_after,
        limit=limit,
        dry_run=False,
        status="trimmed",
        message="IOC table trimmed successfully.",
        dashboard_snapshot=dashboard_snapshot,
        vacuum_recommended=vacuum_recommended,
    )
