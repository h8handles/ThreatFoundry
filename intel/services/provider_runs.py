from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from django.utils import timezone

from intel.models import ProviderRun
from intel.services.common import compact_error, normalize_details


logger = logging.getLogger(__name__)


@dataclass
class ProviderRunRecorder:
    run: ProviderRun

    @classmethod
    def start(
        cls,
        *,
        provider_name: str,
        run_type: str,
        enabled_state: bool | None,
        details: dict | None = None,
    ) -> "ProviderRunRecorder":
        run = ProviderRun.objects.create(
            provider_name=provider_name,
            run_type=run_type,
            status=ProviderRun.Status.SKIPPED,
            enabled_state=enabled_state,
            started_at=timezone.now(),
            details=normalize_details(details),
        )
        _log_provider_run_event("provider_run_started", run=run)
        return cls(run=run)

    def finish(
        self,
        *,
        status: str,
        records_fetched: int | None = None,
        records_created: int | None = None,
        records_updated: int | None = None,
        records_skipped: int | None = None,
        error_message: str | None = None,
        error_type: str | None = None,
        details: dict | None = None,
    ) -> ProviderRun:
        self.run.status = status
        self.run.completed_at = timezone.now()
        if records_fetched is not None:
            self.run.records_fetched = records_fetched
        if records_created is not None:
            self.run.records_created = records_created
        if records_updated is not None:
            self.run.records_updated = records_updated
        if records_skipped is not None:
            self.run.records_skipped = records_skipped
        if error_message is not None:
            self.run.last_error_message = compact_error(error_message)
        if details is not None:
            merged_details = dict(self.run.details or {})
            merged_details.update(normalize_details(details))
            self.run.details = merged_details
        if error_type:
            merged_details = dict(self.run.details or {})
            merged_details["error_type"] = str(error_type)
            self.run.details = merged_details
        self.run.save(
            update_fields=[
                "status",
                "completed_at",
                "records_fetched",
                "records_created",
                "records_updated",
                "records_skipped",
                "last_error_message",
                "details",
            ]
        )
        _log_provider_run_event(
            "provider_run_finished",
            run=self.run,
            error_type=error_type,
        )
        return self.run

    def mark_success(self, **kwargs) -> ProviderRun:
        return self.finish(status=ProviderRun.Status.SUCCESS, **kwargs)

    def mark_failure(self, **kwargs) -> ProviderRun:
        return self.finish(status=ProviderRun.Status.FAILURE, **kwargs)

    def mark_partial(self, **kwargs) -> ProviderRun:
        return self.finish(status=ProviderRun.Status.PARTIAL, **kwargs)

    def mark_skipped(self, **kwargs) -> ProviderRun:
        return self.finish(status=ProviderRun.Status.SKIPPED, **kwargs)


def _log_provider_run_event(
    event: str,
    *,
    run: ProviderRun,
    error_type: str | None = None,
) -> None:
    completed_at = run.completed_at
    duration_seconds = None
    if completed_at is not None and run.started_at is not None:
        duration_seconds = (completed_at - run.started_at).total_seconds()

    resolved_error_type = error_type or (run.details or {}).get("error_type") or ""
    payload = {
        "event": event,
        "provider": run.provider_name,
        "run_type": run.run_type,
        "status": run.status,
        "error_type": resolved_error_type,
        "error_message": run.last_error_message or "",
        "timestamp": timezone.now().isoformat(),
        "started_at": run.started_at.isoformat() if run.started_at else "",
        "completed_at": completed_at.isoformat() if completed_at else "",
        "duration_seconds": duration_seconds,
        "records_fetched": run.records_fetched,
        "records_created": run.records_created,
        "records_updated": run.records_updated,
        "records_skipped": run.records_skipped,
    }
    logger.info(json.dumps(payload, default=str, sort_keys=True))
