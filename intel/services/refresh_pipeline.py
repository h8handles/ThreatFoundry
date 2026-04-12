from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from intel.management.commands.import_alienvault import extract_otx_records
from intel.management.commands.import_urlhaus import extract_urlhaus_records
from intel.models import IngestionRun, IntelIOC, ProviderRunDetail
from intel.services.alienvault import fetch_otx_iocs
from intel.services.dashboard import build_dashboard_context, parse_dashboard_filters
from intel.services.ingestion import (
    normalize_alienvault_record,
    normalize_urlhaus_record,
    upsert_iocs,
)
from intel.services.common import compact_error as _compact_error
from intel.services.provider_registry import PROVIDER_SPECS, get_provider_spec
from intel.services.threatfox import fetch_threatfox_iocs
from intel.services.urlhaus import fetch_recent_urlhaus_iocs
from intel.services.virustotal import (
    UnsupportedVirusTotalLookup,
    VirusTotalNotFound,
    build_lookup,
    enrich_ioc_record,
    throttle_request,
)


logger = logging.getLogger(__name__)


VIRUSTOTAL_SKIP_REASON_LABELS = {
    "already_enriched": "already enriched",
    "unsupported_lookup_type": "unsupported lookup type",
    "not_found": "VT not found",
    "no_changes_after_enrichment": "no changes after enrichment",
    "error": "error",
}


@dataclass(frozen=True)
class RefreshWindow:
    raw: str
    since: datetime | None

    @property
    def days(self) -> int:
        if self.since is None:
            return 1
        delta = timezone.now() - self.since
        if delta.total_seconds() <= 0:
            return 1
        return max(1, math.ceil(delta.total_seconds() / 86400))


@dataclass(frozen=True)
class RefreshProvider:
    key: str
    run_type: str
    execute: Callable[..., "ProviderExecutionResult"] | None


@dataclass
class ProviderExecutionResult:
    provider_name: str
    run_type: str
    status: str
    enabled_state: bool | None
    records_fetched: int = 0
    records_created: int = 0
    records_updated: int = 0
    records_skipped: int = 0
    error_summary: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class RefreshExecutionResult:
    run: IngestionRun
    provider_results: list[ProviderExecutionResult]


def parse_refresh_since(value: str | None) -> RefreshWindow:
    raw = str(value or settings.INTEL_REFRESH_DEFAULT_SINCE).strip()
    if not raw:
        raw = "24h"

    relative_match = re.fullmatch(r"(?i)\s*(\d+)\s*([smhdw])\s*", raw)
    if relative_match:
        count = int(relative_match.group(1))
        unit = relative_match.group(2).lower()
        multiplier = {
            "s": timedelta(seconds=count),
            "m": timedelta(minutes=count),
            "h": timedelta(hours=count),
            "d": timedelta(days=count),
            "w": timedelta(weeks=count),
        }[unit]
        return RefreshWindow(raw=raw, since=timezone.now() - multiplier)

    parsed = parse_datetime(raw)
    if parsed is None:
        raise ValueError(
            "Invalid --since value. Use an ISO datetime such as 2026-04-11T00:00:00Z or a relative window like 24h or 7d."
        )
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.utc)
    return RefreshWindow(raw=raw, since=parsed)


def discover_refresh_providers(provider_name: str | None = None) -> list[RefreshProvider]:
    implemented = {
        "threatfox": RefreshProvider(
            key="threatfox",
            run_type=ProviderRunDetail.RunType.INGEST,
            execute=_run_threatfox,
        ),
        "alienvault": RefreshProvider(
            key="alienvault",
            run_type=ProviderRunDetail.RunType.INGEST,
            execute=_run_alienvault,
        ),
        "urlhaus": RefreshProvider(
            key="urlhaus",
            run_type=ProviderRunDetail.RunType.INGEST,
            execute=_run_urlhaus,
        ),
        "virustotal": RefreshProvider(
            key="virustotal",
            run_type=ProviderRunDetail.RunType.ENRICHMENT,
            execute=_run_virustotal,
        ),
    }

    if provider_name:
        key = provider_name.strip().lower()
        if key not in PROVIDER_SPECS:
            raise ValueError(f"Unknown provider {provider_name!r}.")
        return [
            implemented.get(
                key,
                RefreshProvider(
                    key=key,
                    run_type=ProviderRunDetail.RunType.INGEST,
                    execute=None,
                ),
            )
        ]

    providers: list[RefreshProvider] = []
    for key, spec in PROVIDER_SPECS.items():
        providers.append(
            implemented.get(
                key,
                RefreshProvider(
                    key=key,
                    run_type=(
                        ProviderRunDetail.RunType.ENRICHMENT
                        if spec.category == "enrichment"
                        else ProviderRunDetail.RunType.INGEST
                    ),
                    execute=None,
                ),
            )
        )
    return providers


def run_refresh_pipeline(
    *,
    provider_name: str | None = None,
    timeout: int | None = None,
    since: str | None = None,
    dry_run: bool = False,
    refresh_feed: bool = True,
    trigger: str = "manual",
) -> RefreshExecutionResult:
    refresh_window = parse_refresh_since(since)
    timeout_seconds = timeout or settings.INTEL_REFRESH_TIMEOUT
    providers = discover_refresh_providers(provider_name)
    now = timezone.now()

    with transaction.atomic():
        ingestion_run = IngestionRun.objects.create(
            status=IngestionRun.Status.FAILURE,
            trigger=trigger,
            requested_provider=(provider_name or "").strip().lower(),
            requested_since=refresh_window.raw,
            timeout_seconds=timeout_seconds,
            dry_run=dry_run,
            feed_refreshed=False,
            started_at=now,
            details={
                "schedule": settings.INTEL_REFRESH_SCHEDULE,
            },
        )

    provider_results: list[ProviderExecutionResult] = []
    for provider in providers:
        provider_results.append(
            _run_provider(
                ingestion_run=ingestion_run,
                provider=provider,
                refresh_window=refresh_window,
                timeout_seconds=timeout_seconds,
                dry_run=dry_run,
            )
        )

    feed_snapshot = refresh_dashboard_snapshot() if refresh_feed else {}
    status = _summarize_overall_status(provider_results)
    error_summary = ""
    if provider_results and all(result.status == ProviderRunDetail.Status.FAILURE for result in provider_results):
        error_summary = "All selected providers failed."
    elif not provider_results:
        status = IngestionRun.Status.FAILURE
        error_summary = "No providers were available for refresh."

    _finish_ingestion_run(
        ingestion_run,
        status=status,
        provider_results=provider_results,
        refresh_feed=refresh_feed,
        error_summary=error_summary,
        extra_details={"dashboard_snapshot": feed_snapshot},
    )
    ingestion_run.refresh_from_db()
    return RefreshExecutionResult(run=ingestion_run, provider_results=provider_results)


def refresh_dashboard_snapshot() -> dict:
    context = build_dashboard_context(parse_dashboard_filters({}))
    return {
        "result_count": context["result_count"],
        "has_data": context["has_data"],
        "newest_ingest": context["kpis"]["newest_ingest"].isoformat()
        if context["kpis"]["newest_ingest"]
        else "",
    }


def _run_provider(
    *,
    ingestion_run: IngestionRun,
    provider: RefreshProvider,
    refresh_window: RefreshWindow,
    timeout_seconds: int,
    dry_run: bool,
) -> ProviderExecutionResult:
    spec = get_provider_spec(provider.key)
    enabled_state = spec.is_enabled() if spec else None
    started_at = timezone.now()

    if spec and not enabled_state:
        result = ProviderExecutionResult(
            provider_name=provider.key,
            run_type=provider.run_type,
            status=ProviderRunDetail.Status.SKIPPED,
            enabled_state=enabled_state,
            error_summary=f"{provider.key} is disabled or missing required configuration.",
            details={"reason": "disabled_or_unconfigured"},
        )
        _persist_provider_result(ingestion_run, result, started_at)
        _log_provider_event("provider_skipped", result)
        return result

    if provider.execute is None:
        result = ProviderExecutionResult(
            provider_name=provider.key,
            run_type=provider.run_type,
            status=ProviderRunDetail.Status.SKIPPED,
            enabled_state=enabled_state,
            error_summary=f"{provider.key} is enabled in the registry but no refresh pipeline is implemented yet.",
            details={"reason": "not_implemented"},
        )
        _persist_provider_result(ingestion_run, result, started_at)
        _log_provider_event("provider_skipped", result)
        return result

    try:
        result = provider.execute(
            provider_name=provider.key,
            run_type=provider.run_type,
            enabled_state=enabled_state,
            refresh_window=refresh_window,
            timeout_seconds=timeout_seconds,
            dry_run=dry_run,
        )
    except Exception as exc:
        result = ProviderExecutionResult(
            provider_name=provider.key,
            run_type=provider.run_type,
            status=ProviderRunDetail.Status.FAILURE,
            enabled_state=enabled_state,
            error_summary=str(exc),
            details={"error_type": type(exc).__name__},
        )

    finished_at = timezone.now()
    duration_seconds = (finished_at - started_at).total_seconds()
    details = dict(result.details or {})
    details.setdefault("duration_seconds", duration_seconds)
    result.details = details
    _persist_provider_result(ingestion_run, result, started_at)
    _log_provider_event("provider_finished", result)
    return result


def _persist_provider_result(
    ingestion_run: IngestionRun,
    result: ProviderExecutionResult,
    started_at: datetime,
) -> None:
    ProviderRunDetail.objects.create(
        ingestion_run=ingestion_run,
        provider_name=result.provider_name,
        run_type=result.run_type,
        enabled_state=result.enabled_state,
        status=result.status,
        started_at=started_at,
        finished_at=timezone.now(),
        records_fetched=result.records_fetched,
        records_created=result.records_created,
        records_updated=result.records_updated,
        records_skipped=result.records_skipped,
        error_summary=_compact_error(result.error_summary),
        details=result.details,
    )


def _finish_ingestion_run(
    ingestion_run: IngestionRun,
    *,
    status: str,
    provider_results: list[ProviderExecutionResult],
    refresh_feed: bool,
    error_summary: str = "",
    extra_details: dict | None = None,
) -> None:
    providers_succeeded = sum(result.status == ProviderRunDetail.Status.SUCCESS for result in provider_results)
    providers_failed = sum(result.status == ProviderRunDetail.Status.FAILURE for result in provider_results)
    providers_skipped = sum(
        result.status in {ProviderRunDetail.Status.SKIPPED, ProviderRunDetail.Status.PARTIAL}
        for result in provider_results
    )
    details = dict(ingestion_run.details or {})
    if extra_details:
        details.update(extra_details)

    ingestion_run.status = status
    ingestion_run.finished_at = timezone.now()
    ingestion_run.feed_refreshed = refresh_feed
    ingestion_run.providers_total = len(provider_results)
    ingestion_run.providers_succeeded = providers_succeeded
    ingestion_run.providers_failed = providers_failed
    ingestion_run.providers_skipped = providers_skipped
    ingestion_run.records_created = sum(result.records_created for result in provider_results)
    ingestion_run.records_updated = sum(result.records_updated for result in provider_results)
    ingestion_run.records_skipped = sum(result.records_skipped for result in provider_results)
    ingestion_run.error_summary = _compact_error(error_summary)
    ingestion_run.details = details
    ingestion_run.save(
        update_fields=[
            "status",
            "finished_at",
            "feed_refreshed",
            "providers_total",
            "providers_succeeded",
            "providers_failed",
            "providers_skipped",
            "records_created",
            "records_updated",
            "records_skipped",
            "error_summary",
            "details",
        ]
    )
    _log_provider_event(
        "refresh_finished",
        {
            "run_id": ingestion_run.pk,
            "status": ingestion_run.status,
            "providers_total": ingestion_run.providers_total,
            "providers_failed": ingestion_run.providers_failed,
            "records_created": ingestion_run.records_created,
            "records_updated": ingestion_run.records_updated,
            "records_skipped": ingestion_run.records_skipped,
        },
    )


def _summarize_overall_status(provider_results: list[ProviderExecutionResult]) -> str:
    if not provider_results:
        return IngestionRun.Status.FAILURE
    if any(result.status == ProviderRunDetail.Status.FAILURE for result in provider_results):
        if any(result.status == ProviderRunDetail.Status.SUCCESS for result in provider_results):
            return IngestionRun.Status.PARTIAL
        return IngestionRun.Status.FAILURE
    if any(result.status == ProviderRunDetail.Status.PARTIAL for result in provider_results):
        return IngestionRun.Status.PARTIAL
    return IngestionRun.Status.SUCCESS


def _log_provider_event(event: str, payload) -> None:
    normalized = payload
    if hasattr(payload, "__dataclass_fields__"):
        normalized = asdict(payload)
    logger.info(
        json.dumps(
            {"event": event, "timestamp": timezone.now().isoformat(), **normalized},
            default=str,
            sort_keys=True,
        )
    )


def _run_threatfox(
    *,
    provider_name: str,
    run_type: str,
    enabled_state: bool | None,
    refresh_window: RefreshWindow,
    timeout_seconds: int,
    dry_run: bool,
) -> ProviderExecutionResult:
    payload = fetch_threatfox_iocs(days=refresh_window.days, timeout=timeout_seconds)
    records = payload.get("data") or []
    if not isinstance(records, list):
        raise RuntimeError("ThreatFox response did not include a valid data list.")
    result = upsert_iocs(records, dry_run=dry_run, provider_name=provider_name)
    status = ProviderRunDetail.Status.PARTIAL if result.skipped else ProviderRunDetail.Status.SUCCESS
    return ProviderExecutionResult(
        provider_name=provider_name,
        run_type=run_type,
        status=status,
        enabled_state=enabled_state,
        records_fetched=len(records),
        records_created=result.created,
        records_updated=result.updated,
        records_skipped=result.skipped,
        details={"days": refresh_window.days, "dry_run": dry_run},
    )


def _run_alienvault(
    *,
    provider_name: str,
    run_type: str,
    enabled_state: bool | None,
    refresh_window: RefreshWindow,
    timeout_seconds: int,
    dry_run: bool,
) -> ProviderExecutionResult:
    payload = fetch_otx_iocs(days=refresh_window.days, timeout=timeout_seconds)
    records = extract_otx_records(payload)
    result = upsert_iocs(
        records,
        normalizer=normalize_alienvault_record,
        dry_run=dry_run,
        provider_name=provider_name,
    )
    status = ProviderRunDetail.Status.PARTIAL if result.skipped else ProviderRunDetail.Status.SUCCESS
    return ProviderExecutionResult(
        provider_name=provider_name,
        run_type=run_type,
        status=status,
        enabled_state=enabled_state,
        records_fetched=len(records),
        records_created=result.created,
        records_updated=result.updated,
        records_skipped=result.skipped,
        details={"days": refresh_window.days, "dry_run": dry_run},
    )


def _run_urlhaus(
    *,
    provider_name: str,
    run_type: str,
    enabled_state: bool | None,
    refresh_window: RefreshWindow,
    timeout_seconds: int,
    dry_run: bool,
) -> ProviderExecutionResult:
    payload = fetch_recent_urlhaus_iocs(timeout=timeout_seconds)
    records = extract_urlhaus_records(payload)
    result = upsert_iocs(
        records,
        normalizer=normalize_urlhaus_record,
        dry_run=dry_run,
        provider_name=provider_name,
    )
    status = ProviderRunDetail.Status.PARTIAL if result.skipped else ProviderRunDetail.Status.SUCCESS
    return ProviderExecutionResult(
        provider_name=provider_name,
        run_type=run_type,
        status=status,
        enabled_state=enabled_state,
        records_fetched=len(records),
        records_created=result.created,
        records_updated=result.updated,
        records_skipped=result.skipped,
        details={"recent_only": True, "dry_run": dry_run},
    )


def _run_virustotal(
    *,
    provider_name: str,
    run_type: str,
    enabled_state: bool | None,
    refresh_window: RefreshWindow,
    timeout_seconds: int,
    dry_run: bool,
) -> ProviderExecutionResult:
    queryset = IntelIOC.objects.all()
    if refresh_window.since:
        queryset = queryset.filter(last_ingested_at__gte=refresh_window.since)

    limit = settings.INTEL_REFRESH_VIRUSTOTAL_LIMIT
    candidate_records = list(queryset.order_by("-last_ingested_at", "-created_at", "-id")[:limit])
    records = [
        record
        for record in candidate_records
        if "virustotal" not in (record.enrichment_payloads or {})
    ]
    if not records:
        return ProviderExecutionResult(
            provider_name=provider_name,
            run_type=run_type,
            status=ProviderRunDetail.Status.SKIPPED,
            enabled_state=enabled_state,
            error_summary="No IOC records matched the VirusTotal enrichment scope.",
            details={"limit": limit, "since": refresh_window.raw, "dry_run": dry_run},
        )

    if dry_run:
        return ProviderExecutionResult(
            provider_name=provider_name,
            run_type=run_type,
            status=ProviderRunDetail.Status.SUCCESS,
            enabled_state=enabled_state,
            records_fetched=len(records),
            records_created=0,
            records_updated=0,
            records_skipped=0,
            details={
                "limit": limit,
                "since": refresh_window.raw,
                "dry_run": True,
                "would_enrich": len(records),
            },
        )

    updated = 0
    skipped = 0
    not_found = 0
    unsupported = 0
    diagnostics: list[dict] = []
    skip_breakdown = {
        "already_enriched": 0,
        "unsupported_lookup_type": 0,
        "not_found": 0,
        "no_changes_after_enrichment": 0,
        "error": 0,
    }

    for index, record in enumerate(records, start=1):
        diagnostic = _build_virustotal_record_diagnostic(record, index=index, total=len(records))
        try:
            changed = enrich_ioc_record(record, force=False, timeout=timeout_seconds)
        except UnsupportedVirusTotalLookup as exc:
            unsupported += 1
            skip_breakdown["unsupported_lookup_type"] += 1
            diagnostic.update(
                {
                    "skip_reason": "unsupported_lookup_type",
                    "skip_detail": str(exc),
                    "db_changed": False,
                }
            )
            diagnostics.append(diagnostic)
            _log_provider_event("virustotal_record_evaluated", diagnostic)
            continue
        except VirusTotalNotFound as exc:
            not_found += 1
            skip_breakdown["not_found"] += 1
            diagnostic.update(
                {
                    "skip_reason": "not_found",
                    "skip_detail": str(exc),
                    "db_changed": False,
                }
            )
            diagnostics.append(diagnostic)
            _log_provider_event("virustotal_record_evaluated", diagnostic)
            continue
        except Exception as exc:
            skip_breakdown["error"] += 1
            diagnostic.update(
                {
                    "skip_reason": "error",
                    "skip_detail": str(exc),
                    "db_changed": False,
                    "error_type": type(exc).__name__,
                }
            )
            diagnostics.append(diagnostic)
            _log_provider_event("virustotal_record_evaluated", diagnostic)
            raise RuntimeError(
                f"VirusTotal enrichment failed for IOC {record.pk} ({record.value}): {exc}"
            ) from exc

        if changed:
            updated += 1
            diagnostic.update(
                {
                    "skip_reason": "",
                    "skip_detail": "",
                    "db_changed": True,
                }
            )
        else:
            skipped += 1
            skip_breakdown["no_changes_after_enrichment"] += 1
            diagnostic.update(
                {
                    "skip_reason": "no_changes_after_enrichment",
                    "skip_detail": (
                        "enrich_ioc_record() returned False with force=False; "
                        "the record was treated as already enriched."
                    ),
                    "db_changed": False,
                }
            )

        diagnostics.append(diagnostic)
        _log_provider_event("virustotal_record_evaluated", diagnostic)

        if index < len(records):
            throttle_request(settings.INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS)

    total_skipped = skipped + not_found + unsupported
    status = ProviderRunDetail.Status.SUCCESS
    if updated and total_skipped:
        status = ProviderRunDetail.Status.PARTIAL
    elif not updated and total_skipped:
        status = ProviderRunDetail.Status.SKIPPED

    return ProviderExecutionResult(
        provider_name=provider_name,
        run_type=run_type,
        status=status,
        enabled_state=enabled_state,
        records_fetched=len(records),
        records_created=0,
        records_updated=updated,
        records_skipped=total_skipped,
        details={
            "limit": limit,
            "since": refresh_window.raw,
            "not_found": not_found,
            "unsupported": unsupported,
            "already_enriched": skipped,
            "skip_breakdown": skip_breakdown,
            "record_diagnostics": diagnostics,
        },
        error_summary=_summarize_virustotal_skip_breakdown(skip_breakdown)
        if total_skipped
        else "",
    )


def _build_virustotal_record_diagnostic(record: IntelIOC, *, index: int, total: int) -> dict:
    enrichment_payloads = record.enrichment_payloads or {}
    already_enriched = "virustotal" in enrichment_payloads
    diagnostic = {
        "ioc_id": record.pk,
        "index": index,
        "total": total,
        "value": record.value,
        "value_type": record.value_type,
        "already_enriched": already_enriched,
        "enrichment_payload_type": type(enrichment_payloads).__name__,
        "lookup_supported": False,
        "lookup_object_type": "",
        "lookup_value": "",
    }

    try:
        lookup = build_lookup(record.value, record.value_type)
    except UnsupportedVirusTotalLookup as exc:
        diagnostic["lookup_support_detail"] = str(exc)
        return diagnostic

    diagnostic.update(
        {
            "lookup_supported": True,
            "lookup_object_type": lookup.object_type,
            "lookup_value": lookup.lookup_value,
            "lookup_support_detail": "",
        }
    )
    return diagnostic


def _summarize_virustotal_skip_breakdown(skip_breakdown: dict[str, int]) -> str:
    parts = []
    for key, label in VIRUSTOTAL_SKIP_REASON_LABELS.items():
        count = int(skip_breakdown.get(key) or 0)
        if count:
            parts.append(f"{label}={count}")
    return ", ".join(parts)
