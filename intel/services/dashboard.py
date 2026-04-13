from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
import json
from urllib.parse import urlencode

from django.conf import settings
from django.core.paginator import Paginator
from django.db import connection
from django.db.models import Avg, Case, CharField, Count, DateTimeField, F, FloatField, Max, Min, Q, Value, When
from django.db.models.functions import Coalesce, Greatest, TruncDate
from django.urls import reverse
from django.utils import timezone

from intel.models import IntelIOC, ProviderRun, ProviderRunDetail
from intel.services.common import (
    coerce_int as _coerce_int,
    first_nonempty_text as _first_nonempty_text,
)
from intel.services.provider_registry import build_provider_links, get_provider_availabilities


UNKNOWN_LABEL = "Unknown"
NOT_PROVIDED_LABEL = "Not provided"
CONFIDENCE_ORDER = ["Unknown", "0-24", "25-49", "50-74", "75-100"]
PAGE_SIZE_OPTIONS = [10, 25, 50, 100]
CONFIDENCE_ENABLED_SOURCES = {"threatfox"}
SOURCE_LABEL_OVERRIDES = {
    "alienvault": "AlienVault",
    "threatfox": "ThreatFox",
    "virustotal": "VirusTotal",
    "urlhaus": "URLhaus",
    "abuseipdb": "AbuseIPDB",
    "cisa_kev": "CISA KEV",
    "mitre_attack": "MITRE ATT&CK",
}
DEFAULT_SORT_BY = "ingested"
DEFAULT_SORT_DIRECTION = "desc"
SORT_OPTIONS = {
    "value": ("value", "value_type", "source_name", "id"),
    "type": ("value_type", "value", "source_name", "id"),
    "source": ("source_name", "value", "value_type", "id"),
    "confidence": ("effective_confidence_level", "value", "source_name", "id"),
    "threat": ("threat_type", "value", "source_name", "id"),
    "observed": ("timeline_at", "value", "source_name", "id"),
    "ingested": ("last_ingested_at", "value", "source_name", "id"),
}


@dataclass(frozen=True)
class DashboardFilters:
    start_date: date | None
    end_date: date | None
    value_type: str
    malware_family: str
    threat_type: str
    confidence_band: str
    search: str
    tag: str
    page: int
    page_size: int
    sort_by: str = DEFAULT_SORT_BY
    sort_direction: str = DEFAULT_SORT_DIRECTION


def parse_dashboard_filters(params) -> DashboardFilters:
    """Normalize request query params into safe, typed dashboard filters.

    Handles coercion/validation for dates, paging, and sort controls so query
    builders can rely on canonical filter values.
    """
    start_date = _parse_date(params.get("start_date"))
    end_date = _parse_date(params.get("end_date"))

    if start_date and end_date and start_date > end_date:
        start_date, end_date = end_date, start_date

    page_size = _parse_page_size(params.get("page_size"))

    return DashboardFilters(
        start_date=start_date,
        end_date=end_date,
        value_type=(params.get("value_type") or "").strip(),
        malware_family=(params.get("malware_family") or "").strip(),
        threat_type=(params.get("threat_type") or "").strip(),
        confidence_band=(params.get("confidence_band") or "").strip(),
        search=(params.get("search") or "").strip(),
        tag=(params.get("tag") or "").strip(),
        page=_parse_positive_int(params.get("page"), default=1),
        page_size=page_size,
        sort_by=_parse_sort_by(params.get("sort")),
        sort_direction=_parse_sort_direction(params.get("direction")),
    )


def get_filter_options():
    queryset = _base_queryset()
    return {
        "value_types": list(
            queryset.values_list("value_type", flat=True).distinct().order_by("value_type")
        ),
        "malware_families": list(
            queryset.values_list("malware_bucket", flat=True).distinct().order_by("malware_bucket")
        ),
        "threat_types": list(
            queryset.values_list("threat_bucket", flat=True).distinct().order_by("threat_bucket")
        ),
        "confidence_bands": CONFIDENCE_ORDER,
    }


def build_dashboard_context(filters: DashboardFilters) -> dict:
    """Assemble the full dashboard view-model consumed by templates.

    Includes KPI aggregates, chart-ready datasets, filter and sort UI state,
    provider health, IOC blade summaries, and paginated table rows.
    """
    filtered_queryset = apply_dashboard_filters(_base_queryset(), filters)
    tag_stats = build_tag_stats(filtered_queryset)
    ioc_blades = build_ioc_blades(filtered_queryset)
    provider_availabilities = get_provider_availabilities()
    provider_health = build_provider_health_status(provider_availabilities)

    time_series = list(
        filtered_queryset.annotate(day=TruncDate("timeline_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    type_distribution = list(
        filtered_queryset.values("value_type")
        .annotate(count=Count("id"))
        .order_by("-count", "value_type")
    )

    malware_distribution = list(
        filtered_queryset.values("malware_bucket")
        .annotate(count=Count("id"))
        .order_by("-count", "malware_bucket")[:8]
    )

    threat_distribution = list(
        filtered_queryset.values("threat_bucket")
        .annotate(count=Count("id"))
        .order_by("-count", "threat_bucket")[:6]
    )

    confidence_distribution = _build_confidence_distribution(filtered_queryset)

    summary = filtered_queryset.aggregate(
        total_iocs=Count("id"),
        average_confidence=Avg("effective_confidence_level"),
        newest_ingest=Max("last_ingested_at"),
        oldest_timeline=Min("timeline_at"),
    )

    ordered_queryset = apply_dashboard_sort(filtered_queryset, filters)
    paginator = Paginator(ordered_queryset, filters.page_size)
    page_obj = paginator.get_page(filters.page)
    recent_ioc_rows = [build_dashboard_row(record) for record in page_obj.object_list]
    active_filters = _build_active_filters(filters)
    dashboard_query = _build_dashboard_query(filters, exclude={"page"})

    return {
        "filters": filters,
        "filter_options": get_filter_options(),
        "active_filters": active_filters,
        "has_active_filters": bool(active_filters),
        "kpis": {
            "total_iocs": summary["total_iocs"] or 0,
            "malware_family_count": filtered_queryset.values("malware_bucket").distinct().count(),
            "ioc_type_count": len(type_distribution),
            "unique_tag_count": tag_stats["unique_tag_count"],
            "average_confidence": summary["average_confidence"],
            "newest_ingest": summary["newest_ingest"],
            "oldest_timeline": summary["oldest_timeline"],
        },
        "time_series": {
            "labels": [item["day"].isoformat() for item in time_series if item["day"]],
            "values": [item["count"] for item in time_series if item["day"]],
        },
        "type_distribution": {
            "labels": [item["value_type"] or UNKNOWN_LABEL for item in type_distribution],
            "values": [item["count"] for item in type_distribution],
        },
        "malware_distribution": {
            "labels": [item["malware_bucket"] for item in malware_distribution],
            "values": [item["count"] for item in malware_distribution],
        },
        "confidence_distribution": {
            "labels": [item["label"] for item in confidence_distribution],
            "values": [item["count"] for item in confidence_distribution],
        },
        "threat_distribution": threat_distribution,
        "top_tags": tag_stats["top_tags"],
        "malware_clusters": [
            {
                "label": item["malware_bucket"],
                "count": item["count"],
                "url": _build_malware_family_url(item["malware_bucket"]),
            }
            for item in malware_distribution
            if item["malware_bucket"] != UNKNOWN_LABEL
        ],
        "ioc_blades": ioc_blades,
        "recent_ioc_rows": recent_ioc_rows,
        "page_obj": page_obj,
        "pagination": _build_pagination_context(page_obj, dashboard_query),
        "sort_state": {
            "sort_by": filters.sort_by,
            "direction": filters.sort_direction,
        },
        "sort_headers": _build_sort_headers(filters),
        "page_size_options": _build_page_size_options(
            filters.page_size,
            _build_dashboard_query(filters, exclude={"page", "page_size"}),
        ),
        "provider_availabilities": provider_availabilities,
        "provider_health": provider_health,
        "result_count": summary["total_iocs"] or 0,
        "has_data": bool(summary["total_iocs"]),
    }


def build_provider_health_status(provider_availabilities: list | None = None) -> list[dict]:
    availabilities = provider_availabilities or get_provider_availabilities()
    provider_keys = [item.key for item in availabilities]
    runs_by_provider = _collect_provider_run_history(provider_keys)
    stale_hours = max(int(getattr(settings, "INTEL_PROVIDER_STALE_HOURS", 24)), 1)
    stale_cutoff = timezone.now() - timedelta(hours=stale_hours)

    health_rows = []
    for availability in availabilities:
        events = runs_by_provider.get(availability.key, [])
        latest = events[0] if events else None
        last_success = _first_event_timestamp(events, status=ProviderRun.Status.SUCCESS)
        last_failure_event = _first_event(events, status=ProviderRun.Status.FAILURE)
        last_failure = last_failure_event["timestamp"] if last_failure_event else None
        last_error = (last_failure_event or {}).get("error_message", "")

        health_state = "healthy"
        if not availability.enabled:
            health_state = "warning"
        elif not latest:
            health_state = "stale"
        elif latest["status"] == ProviderRun.Status.FAILURE:
            health_state = "failing"
        elif latest["timestamp"] and latest["timestamp"] < stale_cutoff:
            health_state = "stale"
        elif latest["status"] in {ProviderRun.Status.PARTIAL, ProviderRun.Status.SKIPPED}:
            health_state = "warning"

        health_rows.append(
            {
                "key": availability.key,
                "label": availability.label,
                "enabled": availability.enabled,
                "configured": len(availability.missing_env_vars) == 0,
                "missing_env_vars": list(availability.missing_env_vars),
                "health_state": health_state,
                "latest_status": latest["status"] if latest else "",
                "last_success": last_success,
                "last_failure": last_failure,
                "last_error": last_error,
            }
        )

    return health_rows


def build_detail_context(record: IntelIOC) -> dict:
    """Build normalized IOC detail data for the investigation page."""
    observed_at = _resolve_observed_at(record)
    return {
        "record": record,
        "observed_at": observed_at,
        "tag_list": _normalize_tags(record.tags),
        "overview_items": _build_overview_items(record, observed_at),
        "detail_sections": _build_platform_detail_sections(record),
        "virustotal_context": _build_virustotal_context(record),
        "context_links": _build_record_context_links(record),
    }


def build_malware_family_context(family: str, page: int = 1, page_size: int = 20) -> dict:
    """Build malware family workspace context with aggregates and pagination."""
    cluster_name = (family or "").strip()
    family_queryset = _base_queryset().filter(malware_bucket=cluster_name)
    tag_stats = build_tag_stats(family_queryset)

    summary = family_queryset.aggregate(
        total_iocs=Count("id"),
        average_confidence=Avg("effective_confidence_level"),
        newest_seen=Max("timeline_at"),
        first_seen=Min("timeline_at"),
    )

    time_series = list(
        family_queryset.annotate(day=TruncDate("timeline_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    type_distribution = list(
        family_queryset.values("value_type")
        .annotate(count=Count("id"))
        .order_by("-count", "value_type")[:8]
    )
    source_distribution = list(
        family_queryset.values("source_name")
        .annotate(count=Count("id"))
        .order_by("-count", "source_name")
    )
    threat_distribution = list(
        family_queryset.values("threat_bucket")
        .annotate(count=Count("id"))
        .order_by("-count", "threat_bucket")[:8]
    )

    paginator = Paginator(
        family_queryset.order_by("-timeline_at", "-last_ingested_at", "-id"),
        page_size,
    )
    page_obj = paginator.get_page(page)
    related_ioc_rows = [build_dashboard_row(record) for record in page_obj.object_list]
    family_query = _build_family_query(cluster_name, page_size=page_size, exclude={"page"})

    return {
        "family": cluster_name,
        "family_summary": {
            "total_iocs": summary["total_iocs"] or 0,
            "average_confidence": summary["average_confidence"],
            "first_seen": summary["first_seen"],
            "newest_seen": summary["newest_seen"],
            "source_count": family_queryset.values("source_name").distinct().count(),
            "reporter_count": family_queryset.exclude(reporter="").values("reporter").distinct().count(),
            "unique_type_count": family_queryset.values("value_type").distinct().count(),
        },
        "family_activity": {
            "labels": [item["day"].isoformat() for item in time_series if item["day"]],
            "values": [item["count"] for item in time_series if item["day"]],
        },
        "family_type_distribution": {
            "labels": [item["value_type"] or UNKNOWN_LABEL for item in type_distribution],
            "values": [item["count"] for item in type_distribution],
        },
        "family_source_distribution": {
            "labels": [_format_source_name(item["source_name"]) for item in source_distribution],
            "values": [item["count"] for item in source_distribution],
        },
        "family_threat_distribution": threat_distribution,
        "family_traits": _build_family_traits(family_queryset),
        "family_references": _build_family_references(family_queryset),
        "top_tags": tag_stats["top_tags"],
        "related_ioc_rows": related_ioc_rows,
        "page_obj": page_obj,
        "pagination": _build_pagination_context(page_obj, family_query),
        "page_size_options": _build_page_size_options(
            page_size,
            _build_family_query(cluster_name, page=1, exclude={"page", "page_size"}),
        ),
    }


def build_malware_directory_context(limit: int = 24) -> dict:
    families = list(
        _base_queryset()
        .exclude(malware_bucket=UNKNOWN_LABEL)
        .values("malware_bucket")
        .annotate(
            count=Count("id"),
            newest_seen=Max("timeline_at"),
            source_count=Count("source_name", distinct=True),
        )
        .order_by("-count", "malware_bucket")[:limit]
    )

    return {
        "family_cards": [
            {
                "label": item["malware_bucket"],
                "count": item["count"],
                "newest_seen": item["newest_seen"],
                "source_count": item["source_count"],
                "url": _build_malware_family_url(item["malware_bucket"]),
            }
            for item in families
        ]
    }


def build_dashboard_row(record: IntelIOC) -> dict:
    """Project a raw IOC record into the row schema used by dashboard tables."""
    observed_at = _resolve_observed_at(record)
    summary = _build_dashboard_summary(record)
    contexts = _iter_record_source_contexts(record)
    source_links = _merge_link_entries(*(context["external_links"] for context in contexts))
    return {
        "record": record,
        "observed_at": observed_at,
        "type_label": _format_indicator_type(record.value_type),
        "summary_title": summary["title"],
        "summary_meta": summary["meta"],
        "source_label": _format_source_name(record.source_name),
        "source_badges": [context["source_label"] for context in contexts],
        "source_links": source_links,
        "tag_list": _normalize_tags(record.tags),
        "malware_family": _effective_malware_family(record),
        "malware_family_url": _build_malware_family_url(_effective_malware_family(record)) if _effective_malware_family(record) else "",
    }


def build_ioc_blades(queryset, limit: int = 24) -> list[dict]:
    """Aggregate records by IOC value/type into blade-style search pivots."""
    grouped: dict[tuple[str, str], dict] = {}

    for record in queryset.order_by("-timeline_at", "-last_ingested_at", "-id"):
        key = (record.value_type, record.value)
        blade = grouped.get(key)
        if blade is None:
            blade = {
                "value": record.value,
                "value_type": record.value_type,
                "source_labels": set(),
                "reference_urls": set(),
                "threat_types": set(),
                "malware_families": set(),
                "record_count": 0,
                "latest_observed_at": None,
                "latest_ingested_at": None,
            }
            grouped[key] = blade

        blade["record_count"] += 1
        blade["latest_observed_at"] = _latest_datetime(
            blade["latest_observed_at"],
            record.timeline_at,
        )
        blade["latest_ingested_at"] = _latest_datetime(
            blade["latest_ingested_at"],
            record.last_ingested_at,
        )

        for source_context in _iter_record_source_contexts(record):
            blade["source_labels"].add(source_context["source_label"])
            for link in source_context["external_links"]:
                reference_url = _first_nonempty_text(link.get("url"))
                if reference_url:
                    blade["reference_urls"].add(reference_url)

        effective_threat = _effective_threat_type(record)
        effective_family = _effective_malware_family(record)
        if effective_threat:
            blade["threat_types"].add(effective_threat)
        if effective_family:
            blade["malware_families"].add(effective_family)

    blades = []
    for blade in list(grouped.values())[:limit]:
        source_labels = sorted(blade["source_labels"]) or [UNKNOWN_LABEL]
        threat_types = sorted(blade["threat_types"])
        malware_families = sorted(blade["malware_families"])
        blades.append(
            {
                "value": blade["value"],
                "value_type": blade["value_type"],
                "type_label": _format_indicator_type(blade["value_type"]),
                "source_labels": source_labels,
                "source_summary": ", ".join(source_labels),
                "source_count": len(source_labels),
                "record_count": blade["record_count"],
                "reference_count": len(blade["reference_urls"]),
                "threat_summary": ", ".join(threat_types[:3]) if threat_types else NOT_PROVIDED_LABEL,
                "malware_summary": ", ".join(malware_families[:3]) if malware_families else NOT_PROVIDED_LABEL,
                "latest_observed_at": blade["latest_observed_at"],
                "latest_ingested_at": blade["latest_ingested_at"],
                "url": _build_ioc_blade_url(blade["value"], blade["value_type"]),
            }
        )

    return blades


def build_ioc_blade_detail_context(value: str, value_type: str) -> dict | None:
    """Build detailed source-level context for a single IOC blade."""
    records = list(
        _base_queryset()
        .filter(value=value, value_type=value_type)
        .order_by("-timeline_at", "-last_ingested_at", "-id")
    )
    if not records:
        return None

    source_groups: dict[str, dict] = {}
    latest_observed_at = None
    latest_ingested_at = None
    tags: set[str] = set()
    threat_types: set[str] = set()
    malware_families: set[str] = set()

    for record in records:
        latest_observed_at = _latest_datetime(latest_observed_at, record.timeline_at)
        latest_ingested_at = _latest_datetime(latest_ingested_at, record.last_ingested_at)

        effective_threat = _effective_threat_type(record)
        effective_family = _effective_malware_family(record)
        if effective_threat:
            threat_types.add(effective_threat)
        if effective_family:
            malware_families.add(effective_family)
        for tag in _normalize_tags(record.tags):
            tags.add(tag)

        for source_context in _iter_record_source_contexts(record):
            source_group = source_groups.setdefault(
                source_context["source_key"],
                {
                    "source_label": source_context["source_label"],
                    "record_ids": set(),
                    "references": set(),
                    "external_links": [],
                    "threat_types": set(),
                    "malware_families": set(),
                    "reporters": set(),
                    "tags": set(),
                    "confidence_levels": set(),
                    "last_seen": None,
                },
            )

            if source_context["record_id"]:
                source_group["record_ids"].add(source_context["record_id"])
            if source_context["reference_url"]:
                source_group["references"].add(source_context["reference_url"])
            source_group["external_links"] = _merge_link_entries(
                source_group["external_links"],
                source_context["external_links"],
            )
            if source_context["threat_type"]:
                source_group["threat_types"].add(source_context["threat_type"])
            if source_context["malware_family"]:
                source_group["malware_families"].add(source_context["malware_family"])
            if source_context["reporter"]:
                source_group["reporters"].add(source_context["reporter"])
            if source_context["confidence_level"] is not None:
                source_group["confidence_levels"].add(source_context["confidence_level"])
            for tag in source_context["tags"]:
                source_group["tags"].add(tag)
            source_group["last_seen"] = _latest_datetime(
                source_group["last_seen"],
                source_context["last_seen"],
            )

    source_details = []
    for source_group in sorted(source_groups.values(), key=lambda item: item["source_label"]):
        source_details.append(
            {
                "source_label": source_group["source_label"],
                "record_ids": sorted(source_group["record_ids"]),
                "references": sorted(source_group["references"]),
                "external_links": source_group["external_links"],
                "threat_types": sorted(source_group["threat_types"]) or [NOT_PROVIDED_LABEL],
                "malware_families": sorted(source_group["malware_families"]) or [NOT_PROVIDED_LABEL],
                "reporters": sorted(source_group["reporters"]) or [NOT_PROVIDED_LABEL],
                "tags": sorted(source_group["tags"]),
                "confidence_levels": sorted(source_group["confidence_levels"]),
                "last_seen": source_group["last_seen"],
                "record_count": len(source_group["record_ids"]) or 1,
            }
        )

    return {
        "value": value,
        "value_type": value_type,
        "type_label": _format_indicator_type(value_type),
        "record_count": len(records),
        "source_count": len(source_details),
        "source_details": source_details,
        "source_labels": [item["source_label"] for item in source_details],
        "source_summary": ", ".join(item["source_label"] for item in source_details),
        "latest_observed_at": latest_observed_at,
        "latest_ingested_at": latest_ingested_at,
        "threat_types": sorted(threat_types) or [NOT_PROVIDED_LABEL],
        "malware_families": sorted(malware_families) or [NOT_PROVIDED_LABEL],
        "tags": sorted(tags),
    }


def apply_dashboard_filters(queryset, filters: DashboardFilters):
    """Apply dashboard filters to a queryset in a deterministic order."""
    if filters.start_date:
        queryset = queryset.filter(timeline_at__gte=_start_of_day(filters.start_date))
    if filters.end_date:
        queryset = queryset.filter(timeline_at__lt=_start_of_day(filters.end_date + timedelta(days=1)))
    if filters.value_type:
        queryset = queryset.filter(value_type=filters.value_type)
    if filters.malware_family:
        queryset = queryset.filter(malware_bucket=filters.malware_family)
    if filters.threat_type:
        queryset = queryset.filter(threat_bucket=filters.threat_type)
    if filters.confidence_band:
        queryset = _apply_confidence_filter(queryset, filters.confidence_band)
    if filters.search:
        queryset = queryset.filter(
            Q(value__icontains=filters.search)
            | Q(source_record_id__icontains=filters.search)
            | Q(reference_url__icontains=filters.search)
            | Q(reporter__icontains=filters.search)
        )
    if filters.tag:
        queryset = _filter_queryset_by_tag(queryset, filters.tag)
    return queryset


def apply_dashboard_sort(queryset, filters: DashboardFilters):
    """Apply validated sort criteria with explicit null ordering."""
    field_names = SORT_OPTIONS.get(filters.sort_by, SORT_OPTIONS[DEFAULT_SORT_BY])
    direction = filters.sort_direction
    order_by = []
    for field_name in field_names:
        expression = F(field_name)
        if direction == "asc":
            order_by.append(expression.asc(nulls_last=True))
        else:
            order_by.append(expression.desc(nulls_last=True))
    return queryset.order_by(*order_by)


def queryset_for_dashboard_filters():
    return _base_queryset()


def _build_source_links(
    *,
    provider_name: str,
    value: str,
    value_type: str,
    source_record_id: str = "",
    reference_url: str = "",
    enrichment_summary: dict | None = None,
    external_references=None,
) -> list[dict]:
    return _merge_link_entries(
        _references_for_provider(external_references, provider_name),
        build_provider_links(
            provider_name,
            value=value,
            value_type=value_type,
            source_record_id=source_record_id,
            reference_url=reference_url,
            enrichment_summary=enrichment_summary or {},
        ),
    )


def _normalize_link_entries(value) -> list[dict]:
    if not isinstance(value, list):
        return []

    normalized: list[dict] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        url = _first_nonempty_text(item.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        normalized.append(
            {
                "provider": _first_nonempty_text(item.get("provider")).lower(),
                "label": _first_nonempty_text(item.get("label")) or "External reference",
                "url": url,
                "note": _first_nonempty_text(item.get("note")),
            }
        )
    return normalized


def _merge_link_entries(*sources) -> list[dict]:
    merged: list[dict] = []
    seen: set[str] = set()
    for source in sources:
        for item in _normalize_link_entries(source):
            if item["url"] in seen:
                continue
            seen.add(item["url"])
            merged.append(item)
    return merged


def _references_for_provider(external_references, provider_name: str | None) -> list[dict]:
    provider_key = _first_nonempty_text(provider_name).lower()
    normalized = _normalize_link_entries(external_references)
    if not provider_key:
        return normalized
    return [item for item in normalized if item.get("provider") == provider_key]


def _build_record_context_links(record: IntelIOC) -> list[dict]:
    contexts = _iter_record_source_contexts(record)
    grouped: list[dict] = []
    for context in contexts:
        if not context["external_links"]:
            continue
        grouped.append(
            {
                "provider_key": context["source_key"],
                "provider_label": context["source_label"],
                "links": context["external_links"],
            }
        )
    return grouped


def _parse_sort_by(value: str | None) -> str:
    candidate = _first_nonempty_text(value).lower()
    return candidate if candidate in SORT_OPTIONS else DEFAULT_SORT_BY


def _parse_sort_direction(value: str | None) -> str:
    candidate = _first_nonempty_text(value).lower()
    return candidate if candidate in {"asc", "desc"} else DEFAULT_SORT_DIRECTION


def _build_sort_headers(filters: DashboardFilters) -> dict:
    base_query = _build_dashboard_query(filters, exclude={"page", "sort", "direction"})
    headers: dict[str, dict] = {}
    default_directions = {
        "value": "asc",
        "type": "asc",
        "source": "asc",
        "confidence": "desc",
        "observed": "desc",
        "ingested": "desc",
    }
    labels = {
        "value": "IOC Value",
        "type": "Type",
        "source": "Source",
        "confidence": "Confidence",
        "observed": "Observed",
        "ingested": "Ingested",
    }

    for key, label in labels.items():
        is_active = filters.sort_by == key
        next_direction = "desc" if is_active and filters.sort_direction == "asc" else "asc"
        if not is_active:
            next_direction = default_directions.get(key, "asc")
        headers[key] = {
            "key": key,
            "label": label,
            "active": is_active,
            "direction": filters.sort_direction if is_active else "",
            "indicator": "ASC" if is_active and filters.sort_direction == "asc" else "DESC" if is_active else "",
            "url": f"?{urlencode({**base_query, 'sort': key, 'direction': next_direction, 'page': 1})}",
        }
    return headers


def build_tag_stats(queryset, limit: int = 10) -> dict:
    """Compute unique tag count and top tag frequencies for summary chips."""
    counter: Counter[str] = Counter()

    for tags in queryset.values_list("tags", flat=True):
        for tag in _normalize_tags(tags):
            counter[tag] += 1

    top_tags = [{"label": label, "count": count} for label, count in counter.most_common(limit)]
    return {
        "unique_tag_count": len(counter),
        "top_tags": top_tags,
    }


def _base_queryset():
    return IntelIOC.objects.annotate(
        timeline_at=Coalesce(
            Greatest("first_seen", "last_seen"),
            "last_seen",
            "first_seen",
            "last_ingested_at",
            "created_at",
            output_field=DateTimeField(),
        ),
        malware_bucket=Case(
            When(malware_family__isnull=True, then=Case(
                When(likely_malware_family__isnull=True, then=Value(UNKNOWN_LABEL)),
                When(likely_malware_family="", then=Value(UNKNOWN_LABEL)),
                default="likely_malware_family",
                output_field=CharField(),
            )),
            When(malware_family="", then=Case(
                When(likely_malware_family__isnull=True, then=Value(UNKNOWN_LABEL)),
                When(likely_malware_family="", then=Value(UNKNOWN_LABEL)),
                default="likely_malware_family",
                output_field=CharField(),
            )),
            When(malware_family__iexact=UNKNOWN_LABEL, then=Case(
                When(likely_malware_family__isnull=True, then=Value(UNKNOWN_LABEL)),
                When(likely_malware_family="", then=Value(UNKNOWN_LABEL)),
                default="likely_malware_family",
                output_field=CharField(),
            )),
            default="malware_family",
            output_field=CharField(),
        ),
        threat_bucket=Case(
            When(threat_type__isnull=True, then=Case(
                When(likely_threat_type__isnull=True, then=Value(UNKNOWN_LABEL)),
                When(likely_threat_type="", then=Value(UNKNOWN_LABEL)),
                default="likely_threat_type",
                output_field=CharField(),
            )),
            When(threat_type="", then=Case(
                When(likely_threat_type__isnull=True, then=Value(UNKNOWN_LABEL)),
                When(likely_threat_type="", then=Value(UNKNOWN_LABEL)),
                default="likely_threat_type",
                output_field=CharField(),
            )),
            When(threat_type__iexact=UNKNOWN_LABEL, then=Case(
                When(likely_threat_type__isnull=True, then=Value(UNKNOWN_LABEL)),
                When(likely_threat_type="", then=Value(UNKNOWN_LABEL)),
                default="likely_threat_type",
                output_field=CharField(),
            )),
            default="threat_type",
            output_field=CharField(),
        ),
        effective_confidence_level=Coalesce(
            "calculated_score",
            "derived_confidence_level",
            "confidence_level",
            output_field=FloatField(),
        ),
    )


def _apply_confidence_filter(queryset, band: str):
    queryset = _confidence_scoped_queryset(queryset)
    if band == "Unknown":
        return queryset.filter(effective_confidence_level__isnull=True)
    if band == "0-24":
        return queryset.filter(effective_confidence_level__gte=0, effective_confidence_level__lt=25)
    if band == "25-49":
        return queryset.filter(effective_confidence_level__gte=25, effective_confidence_level__lt=50)
    if band == "50-74":
        return queryset.filter(effective_confidence_level__gte=50, effective_confidence_level__lt=75)
    if band == "75-100":
        return queryset.filter(effective_confidence_level__gte=75)
    return queryset


def _build_confidence_distribution(queryset):
    queryset = _confidence_scoped_queryset(queryset)
    distribution = list(
        queryset.annotate(
            confidence_bucket=Case(
                When(effective_confidence_level__isnull=True, then=Value("Unknown")),
                When(effective_confidence_level__lt=25, then=Value("0-24")),
                When(effective_confidence_level__lt=50, then=Value("25-49")),
                When(effective_confidence_level__lt=75, then=Value("50-74")),
                default=Value("75-100"),
                output_field=CharField(),
            )
        )
        .values("confidence_bucket")
        .annotate(count=Count("id"))
        .order_by("confidence_bucket")
    )

    counts_by_label = {item["confidence_bucket"]: item["count"] for item in distribution}
    return [{"label": label, "count": counts_by_label.get(label, 0)} for label in CONFIDENCE_ORDER]


def _filter_queryset_by_tag(queryset, search_term: str):
    normalized_search = search_term.strip().lower()
    if not normalized_search:
        return queryset

    like_pattern = f"%{normalized_search}%"
    vendor = connection.vendor

    if vendor == "postgresql":
        # Use JSONB expansion in-database for case-insensitive partial tag matching.
        return queryset.extra(
            where=[
                "EXISTS (SELECT 1 FROM jsonb_array_elements_text(tags) AS tag WHERE lower(tag) LIKE %s)"
            ],
            params=[like_pattern],
        )

    if vendor == "sqlite":
        # SQLite JSON1 equivalent for local/dev parity.
        return queryset.extra(
            where=[
                "EXISTS (SELECT 1 FROM json_each(tags) WHERE lower(json_each.value) LIKE %s)"
            ],
            params=[like_pattern],
        )

    # Conservative fallback for unsupported backends.
    return queryset.filter(tags__icontains=search_term)


def _normalize_tags(tags) -> list[str]:
    if isinstance(tags, str):
        tags = [tags]

    normalized = []
    for tag in tags or []:
        cleaned = str(tag).strip()
        if cleaned:
            normalized.append(cleaned)
    return normalized


def _build_dashboard_summary(record: IntelIOC) -> dict:
    raw_payload = _as_dict(record.raw_payload)

    if record.source_name == "alienvault":
        title = _first_nonempty_text(
            raw_payload.get("title"),
            raw_payload.get("description"),
            raw_payload.get("content"),
        )
        meta = [f"Record ID {record.source_record_id}"]
        if record.malware_family:
            meta.append(f"Family {_effective_malware_family(record)}")
        if record.threat_type:
            meta.append(_effective_threat_type(record))
        if _effective_confidence_level(record) is not None:
            meta.append(f"Confidence {_effective_confidence_level(record)}")
        if raw_payload.get("description"):
            meta.append(_compact_text(raw_payload.get("description"), 80))
        return {
            "title": title or "OTX indicator record",
            "meta": meta,
        }

    headline = _first_nonempty_text(
        _effective_threat_type(record),
        _effective_malware_family(record),
        record.reporter,
    )
    meta = []
    if _effective_malware_family(record):
        meta.append(f"Family {_effective_malware_family(record)}")
    if _effective_confidence_level(record) is not None:
        meta.append(f"Confidence {_effective_confidence_level(record)}")
    elif record.reporter:
        meta.append(f"Reporter {record.reporter}")

    return {
        "title": headline or "IOC record",
        "meta": meta,
    }


def _build_overview_items(record: IntelIOC, observed_at) -> list[dict]:
    items = [
        {"label": "IOC Type", "value": _format_indicator_type(record.value_type)},
        {"label": "Observed", "value": _format_datetime(observed_at)},
        {"label": "Last Ingest", "value": _format_datetime(record.last_ingested_at)},
        {"label": "Source", "value": _format_source_name(record.source_name)},
        {"label": "Source Record ID", "value": record.source_record_id},
    ]

    optional_items = [
        ("Threat Type", _effective_threat_type(record)),
        ("Malware Family", _effective_malware_family(record)),
        ("Confidence", str(_effective_confidence_level(record)) if _effective_confidence_level(record) is not None else ""),
        ("Likely Threat Type", record.likely_threat_type),
        ("Likely Malware Family", record.likely_malware_family),
        ("Correlation Score", str(record.derived_confidence_level) if record.derived_confidence_level is not None else ""),
        ("Reporter", record.reporter),
    ]

    for label, value in optional_items:
        text = _first_nonempty_text(value)
        if text:
            items.insert(1, {"label": label, "value": text})

    return items


def _build_platform_detail_sections(record: IntelIOC) -> list[dict]:
    raw_payload = _as_dict(record.raw_payload)

    if record.source_name == "alienvault":
        return [
            {
                "title": "OTX Record Fields",
                "items": [
                    {"label": "Indicator", "value": _display_or_fallback(raw_payload.get("indicator"), record.value)},
                    {"label": "Type", "value": _display_or_fallback(raw_payload.get("type"), record.value_type)},
                    {"label": "Record ID", "value": _display_or_fallback(raw_payload.get("id"), record.source_record_id)},
                ],
            },
            {
                "title": "OTX Narrative",
                "items": [
                    {"label": "Title", "value": _display_or_fallback(raw_payload.get("title"))},
                    {"label": "Description", "value": _display_or_fallback(raw_payload.get("description"))},
                    {"label": "Content", "value": _display_or_fallback(raw_payload.get("content"))},
                ],
            },
        ]

    if record.source_name == "threatfox":
        return [
            {
                "title": "ThreatFox Classification",
                "items": [
                    {"label": "Threat Type", "value": _display_or_fallback(record.threat_type)},
                    {"label": "Malware Family", "value": _display_or_fallback(record.malware_family)},
                    {
                        "label": "Confidence",
                        "value": _display_or_fallback(
                            record.confidence_level if record.confidence_level is not None else ""
                        ),
                    },
                    {"label": "Reporter", "value": _display_or_fallback(record.reporter)},
                ],
            },
            {
                "title": "ThreatFox Timing",
                "items": [
                    {"label": "First Seen", "value": _format_datetime(record.first_seen)},
                    {"label": "Last Seen", "value": _format_datetime(record.last_seen)},
                    {"label": "Reference", "value": _display_or_fallback(record.reference_url)},
                ],
            },
        ]

    return [
        {
            "title": "Source Fields",
            "items": [
                {"label": "Indicator", "value": _display_or_fallback(record.value)},
                {"label": "Type", "value": _display_or_fallback(record.value_type)},
                {"label": "Source Record ID", "value": _display_or_fallback(record.source_record_id)},
            ],
        }
    ]


def _build_virustotal_context(record: IntelIOC) -> dict | None:
    enrichment_payloads = _as_dict(record.enrichment_payloads)
    enrichment = _as_dict(enrichment_payloads.get("virustotal"))
    if not enrichment:
        return None

    summary = _as_dict(enrichment.get("summary"))
    analysis_items = [
        {"label": "Object Type", "value": _display_or_fallback(summary.get("object_type"))},
        {"label": "Detection Ratio", "value": _display_or_fallback(summary.get("detection_ratio"))},
        {
            "label": "Derived Confidence",
            "value": _display_or_fallback(
                summary.get("analysis_score") if summary.get("analysis_score") is not None else ""
            ),
        },
        {"label": "Reputation", "value": _display_or_fallback(summary.get("reputation"))},
        {"label": "Last Analysis", "value": _format_iso_datetime(summary.get("last_analysis_date"))},
        {"label": "Fetched At", "value": _format_iso_datetime(enrichment.get("fetched_at"))},
    ]

    classification_items = [
        {"label": "Threat Label", "value": _display_or_fallback(summary.get("popular_threat_label"))},
        {
            "label": "Malware Candidates",
            "value": _display_or_fallback(_format_ranked_labels(summary.get("popular_threat_names"))),
        },
        {
            "label": "Threat Categories",
            "value": _display_or_fallback(_format_ranked_labels(summary.get("popular_threat_categories"))),
        },
        {
            "label": "Sandbox Families",
            "value": _display_or_fallback(_join_or_fallback(summary.get("sandbox_malware_names"))),
        },
        {
            "label": "Sandbox Categories",
            "value": _display_or_fallback(_join_or_fallback(summary.get("sandbox_categories"))),
        },
        {"label": "Tags", "value": _display_or_fallback(_join_or_fallback(summary.get("tags")))},
    ]

    reference_links = _build_source_links(
        provider_name="virustotal",
        value=record.value,
        value_type=record.value_type,
        enrichment_summary=summary,
        external_references=_references_for_provider(record.external_references, "virustotal"),
    )

    return {
        "reference_url": reference_links[0]["url"] if reference_links else "",
        "reference_note": reference_links[0]["note"] if reference_links else "",
        "reference_links": reference_links,
        "analysis_items": analysis_items,
        "classification_items": classification_items,
        "artifact_items": _build_virustotal_artifact_items(summary),
        "raw_pretty": json.dumps(enrichment.get("raw") or {}, indent=2, sort_keys=True),
    }


def _collect_provider_run_history(provider_keys: list[str]) -> dict[str, list[dict]]:
    history: dict[str, list[dict]] = {key: [] for key in provider_keys}

    direct_runs = ProviderRun.objects.filter(provider_name__in=provider_keys).values(
        "id",
        "provider_name",
        "status",
        "started_at",
        "completed_at",
        "last_error_message",
    )
    for run in direct_runs:
        timestamp = run["completed_at"] or run["started_at"]
        history[run["provider_name"]].append(
            {
                "id": run["id"],
                "status": run["status"],
                "timestamp": timestamp,
                "error_message": run["last_error_message"] or "",
            }
        )

    refresh_runs = ProviderRunDetail.objects.filter(provider_name__in=provider_keys).values(
        "id",
        "provider_name",
        "status",
        "started_at",
        "finished_at",
        "error_summary",
    )
    for run in refresh_runs:
        timestamp = run["finished_at"] or run["started_at"]
        history[run["provider_name"]].append(
            {
                "id": run["id"],
                "status": run["status"],
                "timestamp": timestamp,
                "error_message": run["error_summary"] or "",
            }
        )

    fallback_timestamp = timezone.make_aware(datetime(1970, 1, 1, 0, 0))
    for key, events in history.items():
        events.sort(key=lambda item: (item["timestamp"] or fallback_timestamp, item["id"]), reverse=True)
        history[key] = events
    return history


def _first_event(events: list[dict], status: str) -> dict | None:
    for event in events:
        if event["status"] == status:
            return event
    return None


def _first_event_timestamp(events: list[dict], status: str):
    event = _first_event(events, status=status)
    if event:
        return event["timestamp"]
    return None


def _build_active_filters(filters: DashboardFilters):
    active = []
    for key, label, value in (
        ("start_date", "Start", filters.start_date.isoformat() if filters.start_date else ""),
        ("end_date", "End", filters.end_date.isoformat() if filters.end_date else ""),
        ("value_type", "Type", filters.value_type),
        ("malware_family", "Malware", filters.malware_family),
        ("threat_type", "Threat", filters.threat_type),
        ("confidence_band", "Confidence", filters.confidence_band),
        ("search", "Search", filters.search),
        ("tag", "Tag", filters.tag),
    ):
        if value:
            active.append({"key": key, "label": label, "value": value})
    return active


def _build_family_traits(queryset, limit: int = 8) -> list[dict]:
    counter: Counter[str] = Counter()

    for payload in queryset.values_list("raw_payload", flat=True):
        raw = _as_dict(payload)
        for candidate in (
            raw.get("ioc_type_desc"),
            raw.get("threat_type_desc"),
            raw.get("malware_alias"),
        ):
            text = _first_nonempty_text(candidate)
            if text:
                counter[text] += 1

    if not counter:
        for item in queryset.values("value_type").annotate(count=Count("id")).order_by("-count", "value_type")[:limit]:
            counter[f"Indicator type: {item['value_type']}"] = item["count"]

    return [{"label": label, "count": count} for label, count in counter.most_common(limit)]


def _build_family_references(queryset, limit: int = 12) -> list[dict]:
    references = []
    seen: set[tuple[str, str]] = set()

    for record in queryset.order_by("-timeline_at", "-id")[:200]:
        raw = _as_dict(record.raw_payload)
        for url, title in (
            (record.reference_url, f"{record.value} reference"),
            (
                raw.get("reference"),
                _first_nonempty_text(raw.get("threat_type_desc"), raw.get("ioc_type_desc"), record.value),
            ),
            (
                raw.get("malware_malpedia"),
                f"{record.malware_family or record.value} Malpedia profile",
            ),
        ):
            url_text = _first_nonempty_text(url)
            title_text = _first_nonempty_text(title)
            key = (url_text, title_text)
            if not url_text or key in seen:
                continue
            seen.add(key)
            references.append(
                {
                    "title": title_text,
                    "url": url_text,
                    "meta": " | ".join(
                        [
                            part
                            for part in (
                                _format_source_name(record.source_name),
                                _first_nonempty_text(record.reporter),
                                _format_datetime(record.first_seen or record.last_ingested_at),
                            )
                            if part
                        ]
                    ),
                }
            )
            if len(references) >= limit:
                return references

    return references


def _build_pagination_context(page_obj, base_query: dict) -> dict:
    def page_url(number: int) -> str:
        params = dict(base_query)
        params["page"] = number
        return f"?{urlencode(params)}"

    return {
        "page_number": page_obj.number,
        "num_pages": page_obj.paginator.num_pages,
        "has_previous": page_obj.has_previous(),
        "has_next": page_obj.has_next(),
        "previous_url": page_url(page_obj.previous_page_number()) if page_obj.has_previous() else "",
        "next_url": page_url(page_obj.next_page_number()) if page_obj.has_next() else "",
        "start_index": page_obj.start_index() if page_obj.paginator.count else 0,
        "end_index": page_obj.end_index() if page_obj.paginator.count else 0,
        "total_count": page_obj.paginator.count,
    }


def _build_page_size_options(current_size: int, base_query: dict) -> list[dict]:
    return [
        {
            "value": size,
            "selected": size == current_size,
            "url": f"?{urlencode({**base_query, 'page_size': size})}",
        }
        for size in PAGE_SIZE_OPTIONS
    ]


def _confidence_scoped_queryset(queryset):
    """
    Include native confidence sources plus any IOC we have already enriched.

    That keeps unscored AlienVault rows out of the chart while allowing
    VirusTotal-backed confidence scores to participate once they exist.
    """
    return queryset.filter(
        Q(source_name__in=CONFIDENCE_ENABLED_SOURCES)
        | Q(calculated_score__isnull=False)
        | Q(confidence_level__isnull=False)
        | Q(derived_confidence_level__isnull=False)
    )


def _build_dashboard_query(filters: DashboardFilters, exclude: set[str] | None = None) -> dict:
    exclude = exclude or set()
    query = {}
    values = (
        ("start_date", filters.start_date.isoformat() if filters.start_date else ""),
        ("end_date", filters.end_date.isoformat() if filters.end_date else ""),
        ("value_type", filters.value_type),
        ("malware_family", filters.malware_family),
        ("threat_type", filters.threat_type),
        ("confidence_band", filters.confidence_band),
        ("search", filters.search),
        ("tag", filters.tag),
        ("sort", filters.sort_by),
        ("direction", filters.sort_direction),
        ("page", filters.page),
        ("page_size", filters.page_size),
    )
    for key, value in values:
        if key in exclude:
            continue
        if value not in ("", None):
            query[key] = value
    return query


def _build_family_query(
    family: str,
    page: int = 1,
    page_size: int = 20,
    exclude: set[str] | None = None,
) -> dict:
    exclude = exclude or set()
    query = {"family": family, "page": page, "page_size": page_size}
    for key in list(query):
        if key in exclude:
            query.pop(key, None)
    return query


def _build_malware_family_url(family: str) -> str:
    text = _first_nonempty_text(family)
    if not text:
        return reverse("intel:malware_family")
    return f"{reverse('intel:malware_family')}?{urlencode({'family': text})}"


def _build_ioc_blade_url(value: str, value_type: str) -> str:
    return f"{reverse('intel:ioc_blade_detail')}?{urlencode({'value': value, 'value_type': value_type})}"


def _iter_record_source_contexts(record: IntelIOC) -> list[dict]:
    timeline_at = getattr(record, "timeline_at", None) or _resolve_observed_at(record)
    primary_links = _build_source_links(
        provider_name=record.source_name,
        value=record.value,
        value_type=record.value_type,
        source_record_id=record.source_record_id,
        reference_url=record.reference_url,
        enrichment_summary=None,
        external_references=_references_for_provider(record.external_references, record.source_name),
    )
    contexts = [
        {
            "source_key": str(record.source_name or "").strip().lower() or "unknown",
            "source_label": _format_source_name(record.source_name),
            "record_id": record.source_record_id,
            "reference_url": primary_links[0]["url"] if primary_links else "",
            "external_links": primary_links,
            "threat_type": _first_nonempty_text(record.threat_type),
            "malware_family": _first_nonempty_text(record.malware_family),
            "reporter": _first_nonempty_text(record.reporter),
            "confidence_level": record.confidence_level,
            "tags": _normalize_tags(record.tags),
            "last_seen": timeline_at,
        }
    ]

    enrichment_payloads = _as_dict(record.enrichment_payloads)
    for provider, payload in enrichment_payloads.items():
        summary = _as_dict(_as_dict(payload).get("summary"))
        lookup = _as_dict(_as_dict(payload).get("lookup"))
        provider_key = str(provider or "").strip().lower()
        provider_links = _build_source_links(
            provider_name=provider,
            value=record.value,
            value_type=record.value_type,
            source_record_id=_first_nonempty_text(
                summary.get("object_id"),
                lookup.get("lookup_value"),
            ),
            reference_url=_first_nonempty_text(summary.get("reference_url")),
            enrichment_summary=summary,
            external_references=_references_for_provider(record.external_references, provider),
        )

        contexts.append(
            {
                "source_key": provider_key or "unknown",
                "source_label": _format_source_name(provider),
                "record_id": _first_nonempty_text(
                    summary.get("object_id"),
                    lookup.get("lookup_value"),
                    record.source_record_id,
                ),
                "reference_url": provider_links[0]["url"] if provider_links else "",
                "external_links": provider_links,
                "threat_type": _first_nonempty_text(
                    _first_label(summary.get("popular_threat_categories")),
                    summary.get("popular_threat_label"),
                ),
                "malware_family": _first_nonempty_text(
                    _first_label(summary.get("popular_threat_names")),
                    _first_label(summary.get("sandbox_malware_names")),
                ),
                "reporter": _format_source_name(provider),
                "confidence_level": _coerce_int(summary.get("analysis_score")),
                "tags": _normalize_tags(summary.get("tags")),
                "last_seen": _parse_iso_datetime(summary.get("last_analysis_date"))
                or _parse_iso_datetime(_as_dict(payload).get("fetched_at"))
                or record.last_ingested_at,
            }
        )

    return contexts


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _display_or_fallback(value, fallback: str = NOT_PROVIDED_LABEL):
    text = _first_nonempty_text(value)
    return text or fallback


def _resolve_observed_at(record: IntelIOC):
    return (
        getattr(record, "timeline_at", None)
        or _latest_datetime(record.first_seen, record.last_seen)
        or record.last_ingested_at
        or record.created_at
    )


def _format_datetime(value):
    if not value:
        return "N/A"
    return timezone.localtime(value).strftime("%Y-%m-%d %H:%M")


def _format_indicator_type(value: str) -> str:
    text = _first_nonempty_text(value)
    if not text:
        return UNKNOWN_LABEL
    return text.replace("_", " ")


def _format_source_name(value: str) -> str:
    text = _first_nonempty_text(value)
    if not text:
        return UNKNOWN_LABEL
    normalized = text.lower()
    if normalized in SOURCE_LABEL_OVERRIDES:
        return SOURCE_LABEL_OVERRIDES[normalized]
    return text.replace("_", " ").replace("-", " ").title()


def _effective_threat_type(record: IntelIOC) -> str:
    native = _first_nonempty_text(record.threat_type)
    if native and native.lower() != UNKNOWN_LABEL.lower():
        return native
    return _first_nonempty_text(record.likely_threat_type)


def _effective_malware_family(record: IntelIOC) -> str:
    native = _first_nonempty_text(record.malware_family)
    if native and native.lower() != UNKNOWN_LABEL.lower():
        return native
    return _first_nonempty_text(record.likely_malware_family)


def _effective_confidence_level(record: IntelIOC):
    annotated = getattr(record, "effective_confidence_level", None)
    if annotated is not None:
        return annotated
    if record.calculated_score is not None:
        return record.calculated_score
    if record.derived_confidence_level is not None:
        return record.derived_confidence_level
    return record.confidence_level


def _compact_text(value, max_length: int = 72) -> str:
    text = _first_nonempty_text(value)
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 1].rstrip()}…"


def _format_iso_datetime(value):
    text = _first_nonempty_text(value)
    if not text:
        return "N/A"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return text
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.utc)
    return timezone.localtime(parsed).strftime("%Y-%m-%d %H:%M")


def _parse_iso_datetime(value):
    text = _first_nonempty_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.utc)
    return parsed


def _latest_datetime(current, candidate):
    if candidate is None:
        return current
    if current is None or candidate > current:
        return candidate
    return current


def _format_ranked_labels(items) -> str:
    if not isinstance(items, list):
        return ""

    labels = []
    for item in items:
        if not isinstance(item, dict):
            continue
        label = _first_nonempty_text(item.get("label"))
        count = item.get("count")
        if not label:
            continue
        if count not in (None, ""):
            labels.append(f"{label} ({count})")
        else:
            labels.append(label)
    return ", ".join(labels)


def _join_or_fallback(items) -> str:
    if isinstance(items, str):
        return items
    if not isinstance(items, list):
        return ""
    values = [_first_nonempty_text(item) for item in items]
    return ", ".join(value for value in values if value)


def _first_label(items) -> str:
    if isinstance(items, list) and items:
        first = items[0]
        if isinstance(first, dict):
            return _first_nonempty_text(first.get("label"))
        return _first_nonempty_text(first)
    return ""


def _build_virustotal_artifact_items(summary: dict) -> list[dict]:
    object_type = _first_nonempty_text(summary.get("object_type"))

    if object_type == "file":
        return [
            {"label": "Meaningful Name", "value": _display_or_fallback(summary.get("meaningful_name"))},
            {"label": "Known Names", "value": _display_or_fallback(_join_or_fallback(summary.get("names")))},
            {"label": "Type Description", "value": _display_or_fallback(summary.get("type_description"))},
            {"label": "MD5", "value": _display_or_fallback(summary.get("md5"))},
            {"label": "SHA1", "value": _display_or_fallback(summary.get("sha1"))},
            {"label": "SHA256", "value": _display_or_fallback(summary.get("sha256"))},
        ]

    if object_type == "url":
        return [
            {"label": "Page Title", "value": _display_or_fallback(summary.get("title"))},
            {"label": "URL", "value": _display_or_fallback(summary.get("url"))},
            {"label": "Final URL", "value": _display_or_fallback(summary.get("last_final_url"))},
            {"label": "Categories", "value": _display_or_fallback(_join_or_fallback(summary.get("category_labels")))},
        ]

    if object_type == "domain":
        return [
            {"label": "Domain", "value": _display_or_fallback(summary.get("lookup_value"))},
            {"label": "Categories", "value": _display_or_fallback(_join_or_fallback(summary.get("category_labels")))},
            {"label": "Whois", "value": _display_or_fallback(summary.get("whois"))},
            {"label": "Reputation", "value": _display_or_fallback(summary.get("reputation"))},
        ]

    if object_type == "ip_address":
        return [
            {"label": "IP", "value": _display_or_fallback(summary.get("lookup_value"))},
            {"label": "Country", "value": _display_or_fallback(summary.get("country"))},
            {"label": "AS Owner", "value": _display_or_fallback(summary.get("as_owner"))},
            {"label": "Network", "value": _display_or_fallback(summary.get("network"))},
            {"label": "JARM", "value": _display_or_fallback(summary.get("jarm"))},
        ]

    return [
        {"label": "Lookup Value", "value": _display_or_fallback(summary.get("lookup_value"))},
        {"label": "Reference", "value": _display_or_fallback(summary.get("reference_url"))},
    ]


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _parse_positive_int(value, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def _parse_page_size(value) -> int:
    size = _parse_positive_int(value, default=25)
    if size not in PAGE_SIZE_OPTIONS:
        return 25
    return size


def _start_of_day(day: date):
    dt = datetime.combine(day, time.min)
    if timezone.is_naive(dt):
        return timezone.make_aware(dt, timezone.get_current_timezone())
    return dt
