from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from typing import Any

import requests
from django.conf import settings
from django.db.models import Avg, Count, F, Max, Q, TextField
from django.db.models.functions import Cast, TruncDate
from django.urls import reverse
from django.utils import timezone

from intel.services.dashboard import (
    DashboardFilters,
    UNKNOWN_LABEL,
    apply_dashboard_filters,
    parse_dashboard_filters,
    queryset_for_dashboard_filters,
)


SUPPORTED_SUMMARY_MODES = ("auto", "analyst", "executive", "technical", "brief")
DEFAULT_SUMMARY_MODE = "auto"
MAX_LOOKUP_RESULTS = 5
URL_PATTERN = re.compile(r"https?://[^\s)]+", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
SYSTEM_PROMPT = (
    "You are a SOC and threat-intelligence analyst assistant. Treat the user as a peer analyst. "
    "Use supplied IOC database context as source of truth. Answer broad and narrow IOC questions, "
    "including specific IOC lookups, source comparisons, confidence, trends, suspicious clusters, "
    "enrichment, prioritization, and executive or technical summaries. Do not pretend only one "
    "output mode is allowed. State uncertainty only when data is genuinely missing."
)


class ChatbotServiceError(RuntimeError):
    pass


def build_chat_bootstrap(filters: DashboardFilters) -> dict[str, Any]:
    return {
        "api_url": reverse("intel:analyst_chat_api"),
        "default_mode": DEFAULT_SUMMARY_MODE,
        "supported_modes": list(SUPPORTED_SUMMARY_MODES),
        "filters": _serialize_filters(filters),
        "sample_prompts": [
            "What do we know about 1.2.3.4?",
            "Which source looks most suspicious right now?",
            "What should I investigate first in this IOC set?",
            "Show me the strongest clusters and why they matter.",
            "Give me the analyst view and leadership summary of the current scope.",
            "What enrichment do we have on the top indicators?",
        ],
        "n8n_configured": bool(_n8n_webhook_url()),
        "provider_mode": str(getattr(settings, "INTEL_CHAT_PROVIDER", "hybrid") or "hybrid"),
    }


def build_scope_badges(filters: DashboardFilters) -> list[dict[str, str]]:
    badges = []
    for label, value in (
        ("Start", filters.start_date.isoformat() if filters.start_date else ""),
        ("End", filters.end_date.isoformat() if filters.end_date else ""),
        ("Type", filters.value_type),
        ("Malware", filters.malware_family),
        ("Threat", filters.threat_type),
        ("Confidence", filters.confidence_band),
        ("Search", filters.search),
        ("Tag", filters.tag),
    ):
        if value:
            badges.append({"label": label, "value": value})
    return badges


def build_chat_response(*, user_prompt: str, summary_mode: str | None, filters_payload: Any) -> dict[str, Any]:
    prompt = str(user_prompt or "").strip()
    if not prompt:
        raise ChatbotServiceError("Prompt is required.")

    filters = parse_dashboard_filters(filters_payload if isinstance(filters_payload, Mapping) else {})
    resolved_mode = resolve_summary_mode(summary_mode, prompt)
    context = build_chat_context(filters, prompt)
    provider_payload = {
        "user_query": prompt,
        "summary_mode": resolved_mode,
        "system_prompt": SYSTEM_PROMPT,
        "dashboard_filters": _serialize_filters(filters),
        "ioc_context": context,
    }

    provider_response = _call_chat_provider(provider_payload)
    answer = str(provider_response.get("answer") or provider_response.get("summary") or "").strip()
    if not answer:
        raise ChatbotServiceError("The chat provider returned an empty response.")

    supporting_records = _normalize_record_list(provider_response.get("supporting_records"))
    if not supporting_records:
        if context["lookup"]["found_any"]:
            supporting_records = context["lookup"]["results"][0]["top_records"]
        else:
            supporting_records = context["top_suspicious"][:5]

    return {
        "summary_mode": resolved_mode,
        "answer": answer,
        "provider": str(provider_response.get("provider") or "local-database"),
        "source_of_truth": str(provider_response.get("source_of_truth") or "database"),
        "key_findings": _normalize_text_list(provider_response.get("key_findings")),
        "recommended_actions": _normalize_text_list(provider_response.get("recommended_actions")),
        "uncertainty": _normalize_text_list(provider_response.get("uncertainty")),
        "supporting_records": supporting_records,
        "supporting_data": {
            "source_breakdown": context["source_breakdown"],
            "cluster_breakdown": context["cluster_breakdown"],
            "threat_breakdown": context["threat_breakdown"],
            "confidence_overview": context["confidence_overview"],
            "daily_counts": context["daily_counts"],
            "enrichment_summary": context["enrichment_summary"],
        },
        "lookup": context["lookup"],
        "context_meta": context["metrics"],
        "available_modes": ["analyst", "executive", "technical", "brief"],
    }


def resolve_summary_mode(explicit_mode: str | None, user_prompt: str) -> str:
    candidate = str(explicit_mode or "").strip().lower()
    if candidate in SUPPORTED_SUMMARY_MODES and candidate != "auto":
        return candidate
    lowered = user_prompt.lower()
    if any(term in lowered for term in ("executive", "leadership", "board", "director")):
        return "executive"
    if any(term in lowered for term in ("technical", "deep dive", "exact fields", "raw detail")):
        return "technical"
    if any(term in lowered for term in ("brief", "quick answer", "short answer")):
        return "brief"
    return "analyst"


def build_chat_context(filters: DashboardFilters, user_prompt: str) -> dict[str, Any]:
    queryset = queryset_for_dashboard_filters().annotate(
        raw_payload_text=Cast("raw_payload", output_field=TextField()),
        tags_text=Cast("tags", output_field=TextField()),
    )
    scoped_queryset = apply_dashboard_filters(queryset, filters)
    max_records = int(getattr(settings, "INTEL_CHAT_MAX_CONTEXT_RECORDS", 60))
    records = list(
        scoped_queryset.order_by(
            F("timeline_at").desc(nulls_last=True),
            F("confidence_level").desc(nulls_last=True),
            F("id").desc(),
        )[:max_records]
    )
    normalized_records = [normalize_ioc_record(record) for record in records]

    metrics = scoped_queryset.aggregate(
        total_iocs=Count("id"),
        average_confidence=Avg("confidence_level"),
        latest_observed_at=Max("timeline_at"),
    )
    metrics["total_iocs"] = metrics.get("total_iocs") or 0
    metrics["high_confidence_iocs"] = scoped_queryset.filter(confidence_level__gte=75).count()
    metrics["low_confidence_iocs"] = scoped_queryset.filter(Q(confidence_level__lt=40) | Q(confidence_level__isnull=True)).count()
    metrics["source_count"] = scoped_queryset.values("source_name").distinct().count()

    source_breakdown = list(
        scoped_queryset.values("source_name")
        .annotate(
            count=Count("id"),
            high_confidence_count=Count("id", filter=Q(confidence_level__gte=75)),
            average_confidence=Avg("confidence_level"),
        )
        .order_by("-count", "source_name")[:6]
    )
    cluster_breakdown = list(
        scoped_queryset.exclude(malware_bucket=UNKNOWN_LABEL)
        .values("malware_bucket")
        .annotate(count=Count("id"))
        .order_by("-count", "malware_bucket")[:6]
    )
    threat_breakdown = list(
        scoped_queryset.values("threat_bucket")
        .annotate(count=Count("id"))
        .order_by("-count", "threat_bucket")[:6]
    )
    daily_counts = list(
        scoped_queryset.annotate(day=TruncDate("timeline_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("-day")[:7]
    )
    daily_counts.reverse()

    enrichment_counter = Counter()
    for record in normalized_records:
        for provider in record["enrichment_providers"]:
            enrichment_counter[provider] += 1

    return {
        "scope": _serialize_filters(filters),
        "metrics": {
            "total_iocs": metrics["total_iocs"],
            "high_confidence_iocs": metrics["high_confidence_iocs"],
            "low_confidence_iocs": metrics["low_confidence_iocs"],
            "average_confidence": _round_or_none(metrics.get("average_confidence")),
            "latest_observed_at": _to_iso(metrics.get("latest_observed_at")),
            "source_count": metrics["source_count"],
        },
        "source_breakdown": [
            {
                "source": _normalize_source_name(item.get("source_name")),
                "count": item.get("count", 0),
                "high_confidence_count": item.get("high_confidence_count", 0),
                "average_confidence": _round_or_none(item.get("average_confidence")),
            }
            for item in source_breakdown
        ],
        "cluster_breakdown": [
            {"cluster": item.get("malware_bucket") or UNKNOWN_LABEL, "count": item.get("count", 0)}
            for item in cluster_breakdown
        ],
        "threat_breakdown": [
            {"threat_type": item.get("threat_bucket") or UNKNOWN_LABEL, "count": item.get("count", 0)}
            for item in threat_breakdown
        ],
        "confidence_overview": {
            "known": scoped_queryset.filter(confidence_level__isnull=False).count(),
            "unknown": scoped_queryset.filter(confidence_level__isnull=True).count(),
            "high": scoped_queryset.filter(confidence_level__gte=75).count(),
            "medium": scoped_queryset.filter(confidence_level__gte=40, confidence_level__lt=75).count(),
            "low": scoped_queryset.filter(confidence_level__lt=40).count(),
        },
        "daily_counts": [{"day": item["day"].isoformat() if item["day"] else "", "count": item["count"]} for item in daily_counts],
        "enrichment_summary": {
            "enriched_records": sum(1 for item in normalized_records if item["enrichment_count"]),
            "providers": [{"provider": provider, "count": count} for provider, count in enrichment_counter.most_common(6)],
        },
        "lookup": build_lookup_context(scoped_queryset, user_prompt),
        "top_suspicious": sorted(normalized_records, key=lambda item: (-item["suspicious_score"], item["value"]))[:5],
        "noisy_records": [item for item in normalized_records if item["confidence_level"] is None or item["confidence_level"] < 40][:5],
    }


def build_lookup_context(queryset, user_prompt: str) -> dict[str, Any]:
    targets = extract_query_targets(user_prompt, queryset)
    results = []
    for target in targets:
        matches = _lookup_matches(queryset, target)
        results.append(
            {
                "target": target["value"],
                "target_type": target["target_type"],
                "matched_count": len(matches),
                "top_records": [normalize_ioc_record(record) for record in matches],
            }
        )
    return {
        "targets": targets,
        "has_specific_targets": bool(targets),
        "found_any": any(item["matched_count"] for item in results),
        "results": results,
    }


def extract_query_targets(user_prompt: str, queryset) -> list[dict[str, str]]:
    prompt = str(user_prompt or "")
    lowered = prompt.lower()
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for match in URL_PATTERN.findall(prompt):
        _append_target(targets, seen, "url", match.rstrip(".,);"))
    for match in IP_PATTERN.findall(prompt):
        _append_target(targets, seen, "ip", match)
    for match in HASH_PATTERN.findall(prompt):
        _append_target(targets, seen, "hash", match.lower())
    for match in EMAIL_PATTERN.findall(prompt):
        _append_target(targets, seen, "email", match.lower())
    for match in DOMAIN_PATTERN.findall(prompt):
        if "://" not in match and "@" not in match:
            _append_target(targets, seen, "domain", match.lower().rstrip("."))

    for family in queryset.exclude(malware_bucket=UNKNOWN_LABEL).values_list("malware_bucket", flat=True).distinct():
        family_text = str(family or "").strip()
        if family_text and family_text.lower() in lowered:
            _append_target(targets, seen, "malware_family", family_text)

    return targets


def normalize_ioc_record(record: Any) -> dict[str, Any]:
    enrichment_payloads = record.enrichment_payloads if isinstance(record.enrichment_payloads, dict) else {}
    enrichment_providers = sorted(str(key) for key in enrichment_payloads if str(key).strip())
    latest_observed = getattr(record, "timeline_at", None)
    return {
        "id": getattr(record, "pk", None),
        "detail_url": reverse("intel:ioc_detail", args=[record.pk]) if getattr(record, "pk", None) else "",
        "value": str(getattr(record, "value", "") or ""),
        "value_type": str(getattr(record, "value_type", "") or ""),
        "source_name": _normalize_source_name(getattr(record, "source_name", "")),
        "source_record_id": str(getattr(record, "source_record_id", "") or ""),
        "threat_type": str(getattr(record, "threat_bucket", "") or getattr(record, "threat_type", "") or UNKNOWN_LABEL),
        "malware_family": str(getattr(record, "malware_bucket", "") or getattr(record, "malware_family", "") or UNKNOWN_LABEL),
        "reporter": str(getattr(record, "reporter", "") or ""),
        "confidence_level": getattr(record, "confidence_level", None),
        "timeline_at": _to_iso(latest_observed),
        "reference_url": str(getattr(record, "reference_url", "") or ""),
        "tags": _normalize_text_list(getattr(record, "tags", [])),
        "enrichment_providers": enrichment_providers,
        "enrichment_count": len(enrichment_providers),
        "suspicious_score": _calculate_suspicion_score(getattr(record, "confidence_level", None), latest_observed, len(enrichment_providers)),
    }


def _call_chat_provider(payload: dict[str, Any]) -> dict[str, Any]:
    provider_mode = str(getattr(settings, "INTEL_CHAT_PROVIDER", "hybrid") or "hybrid").strip().lower()
    webhook_url = _n8n_webhook_url()

    if provider_mode == "n8n" and not webhook_url:
        raise ChatbotServiceError("INTEL_CHAT_N8N_WEBHOOK_URL is not configured.")

    if provider_mode in {"n8n", "hybrid"} and webhook_url:
        try:
            return _call_n8n(payload)
        except ChatbotServiceError:
            if provider_mode == "n8n":
                raise

    return _build_local_database_answer(payload)


def _call_n8n(payload: dict[str, Any]) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    bearer = str(getattr(settings, "INTEL_CHAT_N8N_BEARER_TOKEN", "") or "").strip()
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    try:
        response = requests.post(
            _n8n_webhook_url(),
            json=payload,
            headers=headers,
            timeout=int(getattr(settings, "INTEL_CHAT_N8N_TIMEOUT", 20)),
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise ChatbotServiceError(f"n8n request failed: {exc}") from exc
    except ValueError as exc:
        raise ChatbotServiceError("n8n response was not valid JSON.") from exc

    root = data if isinstance(data, Mapping) else {}
    payload_map = root.get("response") if isinstance(root.get("response"), Mapping) else root
    answer = str(payload_map.get("answer") or payload_map.get("summary") or root.get("answer") or "").strip()
    if not answer:
        raise ChatbotServiceError("n8n did not return an answer field.")

    return {
        "answer": answer,
        "key_findings": _normalize_text_list(payload_map.get("key_findings") or root.get("key_findings")),
        "recommended_actions": _normalize_text_list(payload_map.get("recommended_actions") or root.get("recommended_actions")),
        "uncertainty": _normalize_text_list(payload_map.get("uncertainty") or root.get("uncertainty")),
        "supporting_records": _normalize_record_list(payload_map.get("supporting_records") or root.get("supporting_records")),
        "provider": str(payload_map.get("provider") or root.get("provider") or "n8n"),
        "source_of_truth": str(payload_map.get("source_of_truth") or root.get("source_of_truth") or "database"),
    }


def _build_local_database_answer(payload: dict[str, Any]) -> dict[str, Any]:
    query = str(payload.get("user_query") or "").strip()
    mode = str(payload.get("summary_mode") or "analyst").strip()
    lowered = query.lower()
    context = payload.get("ioc_context") if isinstance(payload.get("ioc_context"), Mapping) else {}
    metrics = context.get("metrics", {})
    lookup = context.get("lookup", {})
    source_breakdown = context.get("source_breakdown", [])
    cluster_breakdown = context.get("cluster_breakdown", [])
    threat_breakdown = context.get("threat_breakdown", [])
    top_suspicious = _normalize_record_list(context.get("top_suspicious"))
    noisy_records = _normalize_record_list(context.get("noisy_records"))
    daily_counts = context.get("daily_counts", [])
    enrichment_summary = context.get("enrichment_summary", {})

    if not metrics.get("total_iocs"):
        return {
            "answer": "There are no IOC records in the current scope, so there is nothing to analyze yet.",
            "key_findings": ["The scoped IOC count is 0."],
            "recommended_actions": ["Clear filters or ingest IOC data before using analyst chat."],
            "uncertainty": [],
            "supporting_records": [],
            "provider": "local-database",
            "source_of_truth": "database",
        }

    if lookup.get("has_specific_targets"):
        result = next((item for item in lookup.get("results", []) if item.get("matched_count")), None)
        if result:
            primary = result["top_records"][0]
            findings = [
                f"{result['target']} matched {result['matched_count']} IOC records in scope.",
                f"Top match source is {primary['source_name']} with confidence {primary.get('confidence_level', 'unknown')}.",
                f"Threat type is {primary['threat_type']} and cluster is {primary['malware_family']}.",
            ]
            uncertainty = []
            if primary.get("enrichment_count", 0) == 0:
                uncertainty.append("No stored enrichment payloads are attached to the top match.")
            return {
                "answer": _render_answer(mode, f"{result['target']} is present in the IOC database and should be treated as an active lead.", findings, uncertainty),
                "key_findings": findings,
                "recommended_actions": [
                    "Open the IOC detail page and review source references for the matched records.",
                    "Investigate the highest-confidence match before pivoting into adjacent records.",
                ],
                "uncertainty": uncertainty,
                "supporting_records": result["top_records"],
                "provider": "local-database",
                "source_of_truth": "database",
            }

        target_list = ", ".join(str(item.get("target")) for item in lookup.get("results", [])) or "the requested IOC"
        findings = [
            f"Checked value, source record ID, reference URL, and stored payload text for {target_list}.",
            f"Current scoped database size is {metrics.get('total_iocs', 0)} records.",
        ]
        return {
            "answer": _render_answer(mode, f"No exact IOC match was found for {target_list} in the current scope.", findings, []),
            "key_findings": findings,
            "recommended_actions": ["Clear filters if you want to search the full IOC set.", "Retry the exact observable format if you expected a match."],
            "uncertainty": [],
            "supporting_records": [],
            "provider": "local-database",
            "source_of_truth": "database",
        }

    if "noise" in lowered or "noisy" in lowered:
        findings = [f"Low-confidence or unscored records account for {metrics.get('low_confidence_iocs', 0)} scoped records."]
        if noisy_records:
            findings.append(f"Example noisy IOC is {noisy_records[0]['value']} from {noisy_records[0]['source_name']}.")
        answer = _render_answer(mode, "The noisiest part of this scope is the low-confidence or unscored IOC slice.", findings, [])
        supporting = noisy_records[:5]
    elif any(term in lowered for term in ("source", "sources", "contributor", "contributors", "feed", "provider")):
        top_source = source_breakdown[0] if source_breakdown else {}
        riskiest = max(source_breakdown or [{}], key=lambda item: (item.get("high_confidence_count", 0), item.get("average_confidence") or 0, item.get("count", 0)))
        findings = [
            f"{top_source.get('source', UNKNOWN_LABEL)} contributes the most records in scope ({top_source.get('count', 0)}).",
            f"{riskiest.get('source', UNKNOWN_LABEL)} has the strongest high-confidence signal ({riskiest.get('high_confidence_count', 0)} high-confidence records).",
        ]
        answer = _render_answer(mode, f"{riskiest.get('source', UNKNOWN_LABEL)} is the source I would scrutinize first.", findings, [])
        supporting = top_suspicious[:5]
    elif any(term in lowered for term in ("cluster", "related", "family", "campaign")):
        cluster = cluster_breakdown[0] if cluster_breakdown else {}
        threat = threat_breakdown[0] if threat_breakdown else {}
        findings = []
        if cluster:
            findings.append(f"{cluster.get('cluster')} is the dominant visible cluster with {cluster.get('count', 0)} records.")
        if threat:
            findings.append(f"{threat.get('threat_type')} is the dominant threat pattern with {threat.get('count', 0)} records.")
        answer = _render_answer(mode, "The current scope shows repeatable clustering rather than isolated one-off indicators.", findings, [])
        supporting = top_suspicious[:5]
    elif any(term in lowered for term in ("enrich", "enrichment", "virustotal", "reputation", "context")):
        providers = enrichment_summary.get("providers", [])
        findings = [f"{enrichment_summary.get('enriched_records', 0)} visible records have enrichment payloads attached."]
        if providers:
            findings.append(f"Top enrichment provider in scope is {providers[0].get('provider')} ({providers[0].get('count')}).")
        uncertainty = []
        if not enrichment_summary.get("enriched_records"):
            uncertainty.append("There are no stored enrichment payloads in the current scope.")
        answer = _render_answer(mode, "Stored enrichment is available for part of the current IOC scope." if enrichment_summary.get("enriched_records") else "There is no stored enrichment in the current IOC scope.", findings, uncertainty)
        supporting = [record for record in top_suspicious if record.get("enrichment_count")][:5]
    elif any(term in lowered for term in ("trend", "trends", "recent", "latest", "over time")):
        latest_slice = daily_counts[-1] if daily_counts else {}
        top_source = source_breakdown[0] if source_breakdown else {}
        findings = []
        if latest_slice:
            findings.append(f"Latest observed day in scope is {latest_slice.get('day')} with {latest_slice.get('count')} records.")
        if top_source:
            findings.append(f"Top source in scope is {top_source.get('source')} with {top_source.get('count')} records.")
        uncertainty = []
        if len(daily_counts) < 2:
            uncertainty.append("Time-series depth is limited, so this is a current-state read rather than a robust historical trend.")
        answer = _render_answer(mode, "Current IOC activity is concentrated around the latest visible slice of data.", findings, uncertainty)
        supporting = []
    else:
        top_record = top_suspicious[0] if top_suspicious else {}
        findings = [
            f"The current scope contains {metrics.get('total_iocs', 0)} IOC records across {metrics.get('source_count', 0)} sources.",
            f"High-confidence records in scope: {metrics.get('high_confidence_iocs', 0)}.",
        ]
        if top_record:
            findings.append(f"Strongest visible IOC lead is {top_record['value']} from {top_record['source_name']}.")
        answer = _render_answer(mode, "The current IOC scope has enough signal to answer broad analyst questions directly from the database.", findings, [])
        supporting = top_suspicious[:5]

    return {
        "answer": answer,
        "key_findings": findings,
        "recommended_actions": [
            "Ask for a specific IOC, source comparison, cluster review, or prioritization question to narrow the answer.",
            "Use the supporting records as the first operational leads.",
        ],
        "uncertainty": uncertainty if "uncertainty" in locals() else [],
        "supporting_records": supporting,
        "provider": "local-database",
        "source_of_truth": "database",
    }


def _lookup_matches(queryset, target: dict[str, str]) -> list[Any]:
    value = target["value"]
    if target["target_type"] == "malware_family":
        filtered = queryset.filter(malware_bucket__iexact=value)
    else:
        filtered = queryset.filter(
            Q(value__iexact=value)
            | Q(source_record_id__iexact=value)
            | Q(reference_url__icontains=value)
            | Q(raw_payload_text__icontains=value)
            | Q(tags_text__icontains=value)
        )
    return list(
        filtered.order_by(
            F("confidence_level").desc(nulls_last=True),
            F("timeline_at").desc(nulls_last=True),
            F("id").desc(),
        )[:MAX_LOOKUP_RESULTS]
    )


def _render_answer(mode: str, headline: str, findings: list[str], uncertainty: list[str]) -> str:
    if mode == "brief":
        return headline
    if mode == "executive":
        return " ".join(part for part in (headline, findings[0] if findings else "") if part)
    if mode == "technical":
        pieces = [headline]
        if findings:
            pieces.append(f"Evidence: {'; '.join(findings[:3])}.")
        if uncertainty:
            pieces.append(f"Limits: {'; '.join(uncertainty[:2])}.")
        return " ".join(pieces)
    return " ".join(part for part in (headline, " ".join(findings[:2])) if part)


def _calculate_suspicion_score(confidence_level: Any, observed_at: Any, enrichment_count: int) -> int:
    try:
        confidence = int(confidence_level or 0)
    except (TypeError, ValueError):
        confidence = 0
    recency_bonus = 0
    if observed_at:
        age = timezone.now() - observed_at
        if age.days <= 1:
            recency_bonus = 20
        elif age.days <= 7:
            recency_bonus = 10
    return confidence + recency_bonus + (enrichment_count * 5)


def _n8n_webhook_url() -> str:
    return str(getattr(settings, "INTEL_CHAT_N8N_WEBHOOK_URL", "") or "").strip()


def _serialize_filters(filters: DashboardFilters) -> dict[str, Any]:
    return {
        "start_date": filters.start_date.isoformat() if filters.start_date else "",
        "end_date": filters.end_date.isoformat() if filters.end_date else "",
        "value_type": filters.value_type,
        "malware_family": filters.malware_family,
        "threat_type": filters.threat_type,
        "confidence_band": filters.confidence_band,
        "search": filters.search,
        "tag": filters.tag,
        "sort": filters.sort_by,
        "direction": filters.sort_direction,
        "page_size": filters.page_size,
    }


def _append_target(targets: list[dict[str, str]], seen: set[tuple[str, str]], target_type: str, value: str) -> None:
    cleaned = str(value or "").strip()
    key = (target_type, cleaned.lower())
    if cleaned and key not in seen:
        seen.add(key)
        targets.append({"target_type": target_type, "value": cleaned})


def _normalize_text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _normalize_record_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows = []
    for item in value:
        if isinstance(item, Mapping):
            rows.append(
                {
                    "id": item.get("id"),
                    "detail_url": str(item.get("detail_url") or ""),
                    "value": str(item.get("value") or ""),
                    "value_type": str(item.get("value_type") or ""),
                    "source_name": _normalize_source_name(item.get("source_name")),
                    "source_record_id": str(item.get("source_record_id") or ""),
                    "threat_type": str(item.get("threat_type") or UNKNOWN_LABEL),
                    "malware_family": str(item.get("malware_family") or UNKNOWN_LABEL),
                    "reporter": str(item.get("reporter") or ""),
                    "confidence_level": item.get("confidence_level"),
                    "timeline_at": str(item.get("timeline_at") or ""),
                    "reference_url": str(item.get("reference_url") or ""),
                    "tags": _normalize_text_list(item.get("tags")),
                    "enrichment_providers": _normalize_text_list(item.get("enrichment_providers")),
                    "enrichment_count": int(item.get("enrichment_count") or 0),
                    "suspicious_score": int(item.get("suspicious_score") or 0),
                }
            )
    return rows


def _normalize_source_name(value: Any) -> str:
    text = str(value or "").strip()
    return text.replace("_", " ").replace("-", " ").title() if text else UNKNOWN_LABEL


def _round_or_none(value: Any) -> float | None:
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return None


def _to_iso(value: Any) -> str:
    if value is None:
        return ""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)
