from __future__ import annotations

import ipaddress
import logging
import re
import socket
import uuid
from collections import Counter
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

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
MAX_CONVERSATION_MESSAGES = 8
MAX_CONVERSATION_MESSAGE_CHARS = 900
URL_PATTERN = re.compile(r"https?://[^\s)]+", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
SYSTEM_PROMPT = (
    "You are a SOC and threat-intelligence analyst assistant. Treat the user as a peer analyst. "
    "Use supplied ThreatFoundry IOC context as source of truth, but adapt the answer to the actual "
    "question instead of forcing every response into the same template. Support specific IOC lookups, "
    "malware-family and infrastructure pivots, trend reads, correlation, summaries, prioritization, "
    "hunt ideas, and uncertainty-aware investigation guidance. Be direct about what the data supports, "
    "what is missing, and which next step would most reduce uncertainty."
)
N8N_RESPONSE_CONTRACT = {
    "answer": "Required natural-language answer. n8n may also return summary.",
    "reasoning_summary": "Optional short explanation of how the answer was derived.",
    "confidence": "Optional confidence label or score.",
    "key_findings": "Optional list of supporting findings.",
    "recommended_actions": "Optional list of next investigative actions.",
    "uncertainty": "Optional list of limits or unknowns.",
    "supporting_records": "Optional list of cited IOC records.",
    "cited_iocs": "Optional alternate field for cited IOC records.",
}
QUESTION_RESPONSE_GUIDANCE = {
    "ioc_lookup": "Answer the observable directly, cite matching records, and call out missing enrichment.",
    "malware_family": "Explain the visible family or cluster pattern, then suggest useful pivots.",
    "source_comparison": "Compare sources by volume, confidence, and operational usefulness.",
    "trend": "Emphasize time slices and source changes. Avoid forcing IOC tables when the question is trend-level.",
    "correlation": "Focus on shared family, source, tags, infrastructure, and stored correlation reasons.",
    "summary": "Summarize scope and risk. Keep supporting detail concise.",
    "prioritization": "Rank what to work first and explain why those leads reduce risk or uncertainty.",
    "hunt": "Convert evidence into a hunting hypothesis and concrete pivots.",
    "uncertainty": "Separate what is supported from what is missing or weakly evidenced.",
    "enrichment": "Discuss available provider evidence and enrichment gaps.",
    "open_analysis": "Answer naturally using the most relevant context; do not force a fixed section template.",
}
log = logging.getLogger(__name__)


class ChatbotServiceError(RuntimeError):
    pass


def build_chat_bootstrap(filters: DashboardFilters) -> dict[str, Any]:
    return {
        "api_url": reverse("intel:analyst_chat_api"),
        "popout_url": f"{reverse('intel:analyst_chat')}?popout=1",
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


def build_chat_response(
    *,
    user_prompt: str,
    summary_mode: str | None,
    filters_payload: Any,
    conversation_payload: Any = None,
) -> dict[str, Any]:
    """Build a complete analyst-chat response from UI payload pieces.

    The public chat endpoint sends a natural-language prompt, optional dashboard
    filters, and recent conversation turns. This function separates those pieces
    into explicit provider payload fields so either the local responder or n8n
    receives the same analyst question, scoped IOC context, conversation memory,
    and response contract.
    """
    prompt = str(user_prompt or "").strip()
    if not prompt:
        raise ChatbotServiceError("Prompt is required.")

    filters = parse_dashboard_filters(filters_payload if isinstance(filters_payload, Mapping) else {})
    resolved_mode = resolve_summary_mode(summary_mode, prompt)
    context = build_chat_context(filters, prompt)
    conversation_context = normalize_conversation_context(conversation_payload)
    response_guidance = build_response_guidance(context.get("query_focus", {}), resolved_mode)
    provider_payload = {
        "request_id": uuid.uuid4().hex,
        "user_query": prompt,
        "analyst_question": prompt,
        "summary_mode": resolved_mode,
        "system_instructions": build_system_instructions(resolved_mode, response_guidance),
        "system_prompt": build_system_instructions(resolved_mode, response_guidance),
        "response_guidance": response_guidance,
        "dashboard_filters": _serialize_filters(filters),
        "conversation_context": conversation_context,
        "ioc_context": context,
    }

    provider_response = _call_chat_provider(provider_payload)
    answer = str(provider_response.get("answer") or provider_response.get("summary") or "").strip()
    if not answer:
        raise ChatbotServiceError("The chat provider returned an empty response.")

    if "supporting_records" in provider_response:
        supporting_records = _normalize_record_list(provider_response.get("supporting_records"))
    else:
        supporting_records = default_supporting_records_for_response(context)

    return {
        "summary_mode": resolved_mode,
        "answer": answer,
        "provider": str(provider_response.get("provider") or "local-database"),
        "source_of_truth": str(provider_response.get("source_of_truth") or "database"),
        "reasoning_summary": str(provider_response.get("reasoning_summary") or "").strip(),
        "confidence": provider_response.get("confidence") or "",
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


def build_system_instructions(summary_mode: str, response_guidance: Mapping[str, Any] | None = None) -> str:
    mode_guidance = {
        "analyst": "Use the structure that best fits the question. Lead with the answer, then add evidence or next steps only when useful.",
        "technical": "Favor precise IOC fields, source names, confidence, enrichment, and pivot details. Avoid executive gloss.",
        "executive": "Keep the answer business-readable and concise. Emphasize risk, impact, confidence, and decisions.",
        "brief": "Answer in a short paragraph or a few bullets. Do not include sections unless they clarify the answer.",
    }.get(summary_mode, "Adapt the format to the analyst question.")
    guidance_text = ""
    if isinstance(response_guidance, Mapping):
        guidance_text = " ".join(str(item) for item in response_guidance.get("instructions", []) if str(item).strip())
    return " ".join(part for part in (SYSTEM_PROMPT, mode_guidance, guidance_text) if part)


def build_response_guidance(query_focus: Mapping[str, Any], summary_mode: str) -> dict[str, Any]:
    intents = list(query_focus.get("intents") or ["open_analysis"]) if isinstance(query_focus, Mapping) else ["open_analysis"]
    instructions = [QUESTION_RESPONSE_GUIDANCE.get(intent, QUESTION_RESPONSE_GUIDANCE["open_analysis"]) for intent in intents]
    if summary_mode == "brief":
        instructions.append("Keep optional fields sparse; do not add supporting records unless they directly answer the question.")
    elif summary_mode == "executive":
        instructions.append("Prefer decision-ready risk language over raw IOC enumeration.")
    return {
        "intents": intents,
        "mode": summary_mode,
        "instructions": _dedupe_text(instructions),
        "allow_sparse_optional_fields": True,
    }


def normalize_conversation_context(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []

    messages = []
    for item in value[-MAX_CONVERSATION_MESSAGES:]:
        if not isinstance(item, Mapping):
            continue
        role = str(item.get("role") or "").strip().lower()
        if role not in {"user", "assistant"}:
            continue
        content = str(item.get("content") or item.get("answer") or "").strip()
        if not content:
            continue
        messages.append(
            {
                "role": role,
                "content": content[:MAX_CONVERSATION_MESSAGE_CHARS],
            }
        )
    return messages


def default_supporting_records_for_response(context: Mapping[str, Any]) -> list[dict[str, Any]]:
    lookup = context.get("lookup", {}) if isinstance(context, Mapping) else {}
    if isinstance(lookup, Mapping) and lookup.get("found_any"):
        first_result = next((item for item in lookup.get("results", []) if item.get("matched_count")), {})
        return _normalize_record_list(first_result.get("top_records"))

    query_focus = context.get("query_focus", {}) if isinstance(context, Mapping) else {}
    intents = set(query_focus.get("intents") or []) if isinstance(query_focus, Mapping) else set()
    if _should_include_record_support(intents):
        return _normalize_record_list(context.get("focused_records"))[:5]
    return []


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
    """Select IOC context that is relevant to the analyst's question.

    The assistant should answer open-ended questions without drowning the model
    or workflow in the entire database. This context builder applies dashboard
    filters, keeps bounded recent records, extracts specific observables from
    the prompt, and returns aggregate slices for trends, sources, enrichment,
    clusters, prioritization, and follow-up investigation.
    """
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

    query_focus = classify_query_focus(user_prompt)
    lookup = build_lookup_context(scoped_queryset, user_prompt)
    top_suspicious = sorted(normalized_records, key=lambda item: (-item["suspicious_score"], item["value"]))[:5]
    focused_records = select_focused_records(
        normalized_records=normalized_records,
        lookup=lookup,
        query_focus=query_focus,
    )

    return {
        "scope": _serialize_filters(filters),
        "query_focus": query_focus,
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
        "lookup": lookup,
        "focused_records": focused_records,
        "top_suspicious": top_suspicious,
        "noisy_records": [item for item in normalized_records if item["confidence_level"] is None or item["confidence_level"] < 40][:5],
    }


def classify_query_focus(user_prompt: str) -> dict[str, Any]:
    lowered = str(user_prompt or "").lower()
    focus_terms = {
        "ioc_lookup": ("what do we know about", "lookup", "ioc", "indicator", "observable"),
        "malware_family": ("malware", "family", "cluster", "campaign"),
        "source_comparison": ("source", "sources", "contributor", "contributors", "feed", "provider"),
        "trend": ("trend", "recent", "latest", "over time", "spike", "change"),
        "correlation": ("correlate", "correlation", "related", "overlap", "same infrastructure", "same actor"),
        "summary": ("summarize", "summary", "brief", "executive", "overview"),
        "prioritization": ("prioritize", "first", "triage", "highest risk", "most suspicious"),
        "hunt": ("hunt", "hunting", "hypothesis", "pivot", "investigate next"),
        "uncertainty": ("uncertain", "confidence", "how sure", "missing", "unknown", "gap"),
        "enrichment": ("enrich", "enrichment", "reputation", "virustotal", "whois", "dns"),
    }
    matched = [name for name, terms in focus_terms.items() if any(term in lowered for term in terms)]
    return {
        "intents": matched or ["open_analysis"],
        "requires_specific_ioc": any(term in lowered for term in ("what do we know about", "lookup", "indicator", "observable")),
        "prefers_actions": any(term in lowered for term in ("what should", "next", "prioritize", "triage", "hunt", "investigate")),
    }


def select_focused_records(
    *,
    normalized_records: list[dict[str, Any]],
    lookup: Mapping[str, Any],
    query_focus: Mapping[str, Any],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_ids: set[Any] = set()

    for result in lookup.get("results", []) if isinstance(lookup, Mapping) else []:
        if not isinstance(result, Mapping):
            continue
        for record in _normalize_record_list(result.get("top_records")):
            if record.get("id") not in seen_ids:
                records.append(record)
                seen_ids.add(record.get("id"))

    intents = set(query_focus.get("intents") or []) if isinstance(query_focus, Mapping) else set()
    candidate_records = list(normalized_records)
    if "enrichment" in intents:
        candidate_records = [record for record in candidate_records if record.get("enrichment_count")] or candidate_records
    if "uncertainty" in intents:
        candidate_records = sorted(candidate_records, key=lambda item: (item.get("confidence_level") is not None, item.get("confidence_level") or 0))
    else:
        candidate_records = sorted(candidate_records, key=lambda item: (-item.get("suspicious_score", 0), item.get("value", "")))

    for record in candidate_records:
        if len(records) >= 8:
            break
        if record.get("id") not in seen_ids:
            records.append(record)
            seen_ids.add(record.get("id"))
    return records


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
        "correlation_reasons": _normalize_text_list(getattr(record, "correlation_reasons", [])),
        "enrichment_providers": enrichment_providers,
        "enrichment_count": len(enrichment_providers),
        "calculated_score": getattr(record, "calculated_score", None),
        "suspicious_score": _calculate_suspicion_score(getattr(record, "confidence_level", None), latest_observed, len(enrichment_providers)),
    }


def _call_chat_provider(payload: dict[str, Any]) -> dict[str, Any]:
    """Route analyst chat to n8n when configured, otherwise use local fallback."""
    provider_mode = str(getattr(settings, "INTEL_CHAT_PROVIDER", "hybrid") or "hybrid").strip().lower()
    webhook_url = _n8n_webhook_url()

    if provider_mode == "n8n" and not webhook_url:
        raise ChatbotServiceError("INTEL_CHAT_N8N_WEBHOOK_URL is not configured.")

    if provider_mode in {"n8n", "hybrid"} and webhook_url:
        try:
            return _call_n8n(payload)
        except ChatbotServiceError as exc:
            log.warning("Analyst chat n8n provider failed; provider_mode=%s error=%s", provider_mode, exc)
            if provider_mode == "n8n":
                raise

    return _build_local_database_answer(payload)


def _call_n8n(payload: dict[str, Any]) -> dict[str, Any]:
    """Send the normalized analyst payload to the configured n8n webhook.

    The response parser accepts a few common n8n output shapes while still
    requiring a usable `answer` field. Optional fields remain optional so the
    workflow can answer flexibly instead of forcing every response into one
    rigid template.
    """
    headers = {"Content-Type": "application/json"}
    bearer = str(getattr(settings, "INTEL_CHAT_N8N_BEARER_TOKEN", "") or "").strip()
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    webhook_url = _validated_n8n_webhook_url()
    n8n_payload = _build_n8n_payload(payload)
    log.info("Sending analyst chat request to n8n webhook host=%s", urlparse(webhook_url).hostname)

    try:
        response = requests.post(
            webhook_url,
            json=n8n_payload,
            headers=headers,
            timeout=int(getattr(settings, "INTEL_CHAT_N8N_TIMEOUT", 20)),
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        raise ChatbotServiceError(f"n8n request failed: {exc}") from exc
    except ValueError as exc:
        raise ChatbotServiceError("n8n response was not valid JSON.") from exc

    root = _unwrap_n8n_response(data)
    payload_map = root.get("response") if isinstance(root.get("response"), Mapping) else root
    answer = str(payload_map.get("answer") or payload_map.get("summary") or root.get("answer") or "").strip()
    if not answer:
        raise ChatbotServiceError("n8n did not return an answer field.")

    return {
        "answer": answer,
        "reasoning_summary": str(payload_map.get("reasoning_summary") or payload_map.get("reasoning") or root.get("reasoning_summary") or "").strip(),
        "confidence": payload_map.get("confidence") or root.get("confidence") or "",
        "key_findings": _normalize_text_list(payload_map.get("key_findings") or root.get("key_findings")),
        "recommended_actions": _normalize_text_list(
            payload_map.get("recommended_actions")
            or payload_map.get("suggested_next_actions")
            or payload_map.get("next_actions")
            or root.get("recommended_actions")
        ),
        "uncertainty": _normalize_text_list(payload_map.get("uncertainty") or root.get("uncertainty")),
        "supporting_records": _normalize_record_list(
            payload_map.get("supporting_records")
            or payload_map.get("cited_iocs")
            or payload_map.get("citations")
            or root.get("supporting_records")
        ),
        "provider": str(payload_map.get("provider") or root.get("provider") or "n8n"),
        "source_of_truth": str(payload_map.get("source_of_truth") or root.get("source_of_truth") or "database"),
    }


def _unwrap_n8n_response(data: Any) -> dict[str, Any]:
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, Mapping):
            if isinstance(first.get("json"), Mapping):
                return dict(first["json"])
            return dict(first)
    if isinstance(data, Mapping):
        if isinstance(data.get("json"), Mapping):
            return dict(data["json"])
        return dict(data)
    return {}


def _build_local_database_answer(payload: dict[str, Any]) -> dict[str, Any]:
    query = str(payload.get("user_query") or "").strip()
    mode = str(payload.get("summary_mode") or "analyst").strip()
    lowered = query.lower()
    context = payload.get("ioc_context") if isinstance(payload.get("ioc_context"), Mapping) else {}
    metrics = context.get("metrics", {})
    lookup = context.get("lookup", {})
    query_focus = context.get("query_focus", {})
    source_breakdown = context.get("source_breakdown", [])
    cluster_breakdown = context.get("cluster_breakdown", [])
    threat_breakdown = context.get("threat_breakdown", [])
    confidence_overview = context.get("confidence_overview", {})
    top_suspicious = _normalize_record_list(context.get("top_suspicious"))
    focused_records = _normalize_record_list(context.get("focused_records")) or top_suspicious
    noisy_records = _normalize_record_list(context.get("noisy_records"))
    daily_counts = context.get("daily_counts", [])
    enrichment_summary = context.get("enrichment_summary", {})
    intents = set(query_focus.get("intents") or []) if isinstance(query_focus, Mapping) else set()

    if not metrics.get("total_iocs"):
        return {
            "answer": "There are no IOC records in the current scope, so there is nothing to analyze yet.",
            "reasoning_summary": "No scoped IOC records were available to analyze.",
            "confidence": "low",
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
                "answer": _render_answer(
                    mode,
                    f"{result['target']} is present in the IOC database and should be treated as an active lead.",
                    findings,
                    uncertainty,
                    question_intents=intents,
                ),
                "reasoning_summary": "The local provider found an exact target match and summarized the strongest matching record.",
                "confidence": _local_confidence_label(metrics, result["top_records"]),
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
            "answer": _render_answer(
                mode,
                f"No exact IOC match was found for {target_list} in the current scope.",
                findings,
                [],
                question_intents=intents,
            ),
            "reasoning_summary": "The local provider searched IOC value, source record ID, reference URL, tags, and raw payload text.",
            "confidence": "medium",
            "key_findings": findings,
            "recommended_actions": ["Clear filters if you want to search the full IOC set.", "Retry the exact observable format if you expected a match."],
            "uncertainty": [],
            "supporting_records": [],
            "provider": "local-database",
            "source_of_truth": "database",
        }

    if "noise" in lowered or "noisy" in lowered or ("uncertainty" in intents and "hunt" not in intents and "prioritization" not in intents):
        findings = [f"Low-confidence or unscored records account for {metrics.get('low_confidence_iocs', 0)} scoped records."]
        if noisy_records:
            findings.append(f"Example noisy IOC is {noisy_records[0]['value']} from {noisy_records[0]['source_name']}.")
        uncertainty = ["Low or missing confidence limits prioritization quality until those records are enriched or cross-sourced."]
        answer = _render_answer(mode, "The noisiest part of this scope is the low-confidence or unscored IOC slice.", findings, uncertainty, question_intents=intents)
        supporting = noisy_records[:5]
    elif any(term in lowered for term in ("source", "sources", "contributor", "contributors", "feed", "provider")):
        top_source = source_breakdown[0] if source_breakdown else {}
        riskiest = max(source_breakdown or [{}], key=lambda item: (item.get("high_confidence_count", 0), item.get("average_confidence") or 0, item.get("count", 0)))
        findings = [
            f"{top_source.get('source', UNKNOWN_LABEL)} contributes the most records in scope ({top_source.get('count', 0)}).",
            f"{riskiest.get('source', UNKNOWN_LABEL)} has the strongest high-confidence signal ({riskiest.get('high_confidence_count', 0)} high-confidence records).",
        ]
        answer = _render_answer(mode, f"{riskiest.get('source', UNKNOWN_LABEL)} is the source I would scrutinize first.", findings, [], question_intents=intents)
        supporting = focused_records[:5] if _should_include_record_support(intents) else []
    elif any(term in lowered for term in ("cluster", "related", "family", "campaign", "overlap", "correlat")):
        cluster = cluster_breakdown[0] if cluster_breakdown else {}
        threat = threat_breakdown[0] if threat_breakdown else {}
        findings = []
        if cluster:
            findings.append(f"{cluster.get('cluster')} is the dominant visible cluster with {cluster.get('count', 0)} records.")
        if threat:
            findings.append(f"{threat.get('threat_type')} is the dominant threat pattern with {threat.get('count', 0)} records.")
        if any(record.get("correlation_reasons") for record in focused_records):
            findings.append("Some focused records include stored correlation reasons that can support pivoting.")
        answer = _render_answer(mode, "The current scope shows repeatable clustering rather than isolated one-off indicators.", findings, [], question_intents=intents)
        supporting = focused_records[:5] if _should_include_record_support(intents) else []
    elif any(term in lowered for term in ("enrich", "enrichment", "virustotal", "reputation", "context")):
        providers = enrichment_summary.get("providers", [])
        findings = [f"{enrichment_summary.get('enriched_records', 0)} visible records have enrichment payloads attached."]
        if providers:
            findings.append(f"Top enrichment provider in scope is {providers[0].get('provider')} ({providers[0].get('count')}).")
        uncertainty = []
        if not enrichment_summary.get("enriched_records"):
            uncertainty.append("There are no stored enrichment payloads in the current scope.")
        answer = _render_answer(
            mode,
            "Stored enrichment is available for part of the current IOC scope." if enrichment_summary.get("enriched_records") else "There is no stored enrichment in the current IOC scope.",
            findings,
            uncertainty,
            question_intents=intents,
        )
        supporting = [record for record in focused_records if record.get("enrichment_count")][:5]
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
        answer = _render_answer(mode, "Current IOC activity is concentrated around the latest visible slice of data.", findings, uncertainty, question_intents=intents)
        supporting = []
    elif any(term in lowered for term in ("hunt", "hunting", "hypothesis", "pivot")):
        findings = [
            f"Start with {focused_records[0]['value']} from {focused_records[0]['source_name']}." if focused_records else "No focused IOC lead is available in the current scope.",
            f"High-confidence records available for hunting pivots: {metrics.get('high_confidence_iocs', 0)}.",
        ]
        if cluster_breakdown:
            findings.append(f"Use {cluster_breakdown[0].get('cluster')} as the first malware-family pivot.")
        answer = _render_answer(mode, "A practical hunt should begin with the highest-confidence IOC, then pivot through shared source, family, tags, and enrichment.", findings, [], question_intents=intents)
        supporting = focused_records[:5] if _should_include_record_support(intents) else []
    else:
        top_record = focused_records[0] if focused_records else {}
        findings = [
            f"The current scope contains {metrics.get('total_iocs', 0)} IOC records across {metrics.get('source_count', 0)} sources.",
            f"High-confidence records in scope: {metrics.get('high_confidence_iocs', 0)}.",
        ]
        if confidence_overview:
            findings.append(
                f"Confidence spread is high={confidence_overview.get('high', 0)}, medium={confidence_overview.get('medium', 0)}, low={confidence_overview.get('low', 0)}, unknown={confidence_overview.get('unknown', 0)}."
            )
        if top_record:
            findings.append(f"Strongest visible IOC lead is {top_record['value']} from {top_record['source_name']}.")
        answer = _render_answer(mode, _default_open_answer_headline(query, intents), findings, [], question_intents=intents)
        supporting = focused_records[:5] if _should_include_record_support(intents) else []

    return {
        "answer": answer,
        "reasoning_summary": "Local fallback classified the analyst question, selected matching IOC context, and summarized database-backed evidence.",
        "confidence": _local_confidence_label(metrics, supporting),
        "key_findings": findings,
        "recommended_actions": _recommended_actions_for_intents(intents),
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


def _default_open_answer_headline(query: str, intents: set[str]) -> str:
    if "prioritization" in intents:
        return "Prioritize the strongest visible IOC leads first, then validate whether they share source, family, or enrichment evidence."
    if "summary" in intents:
        return "The current IOC scope is suitable for a concise situational summary backed by source and confidence distribution."
    if query.endswith("?"):
        return "Based on the current IOC scope, the strongest answer is driven by confidence, recency, source concentration, and enrichment coverage."
    return "The current IOC scope has enough signal to support broad analyst follow-up from the database."


def _recommended_actions_for_intents(intents: set[str]) -> list[str]:
    if "hunt" in intents:
        return [
            "Pivot from the highest-confidence IOC into shared malware family, source, tags, and enrichment provider evidence.",
            "Promote any repeated infrastructure or source overlap into a hunt hypothesis before broadening the scope.",
        ]
    if "uncertainty" in intents:
        return [
            "Enrich low-confidence or unscored records before making a priority call.",
            "Compare suspicious records across at least one independent source before escalation.",
        ]
    if "trend" in intents:
        return [
            "Review the newest daily slice against source and malware-family concentration.",
            "Broaden the date filter if you need a historical trend instead of a current-state read.",
        ]
    if "summary" in intents:
        return [
            "Use a follow-up question to drill into a source, cluster, or confidence band from the summary.",
        ]
    if "open_analysis" in intents:
        return [
            "Ask a more specific follow-up when you want pivots, source comparison, or record-level evidence.",
        ]
    return [
        "Use the supporting records as the first operational leads.",
        "Ask a follow-up about a specific IOC, source, family, trend, or hunt path to narrow the analysis.",
    ]


def _local_confidence_label(metrics: Mapping[str, Any], supporting_records: list[dict[str, Any]]) -> str:
    if not metrics.get("total_iocs"):
        return "low"
    if supporting_records and any((record.get("confidence_level") or 0) >= 75 for record in supporting_records):
        return "medium-high"
    if metrics.get("high_confidence_iocs", 0):
        return "medium"
    return "low-medium"


def _should_include_record_support(intents: set[str]) -> bool:
    return bool(
        intents.intersection(
            {
                "prioritization",
                "hunt",
                "correlation",
                "malware_family",
                "enrichment",
                "ioc_lookup",
                "source_comparison",
            }
        )
    )


def _render_answer(
    mode: str,
    headline: str,
    findings: list[str],
    uncertainty: list[str],
    *,
    question_intents: set[str] | None = None,
) -> str:
    intents = question_intents or set()
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
    if "hunt" in intents or "prioritization" in intents:
        action_hint = "Next, work the highest-confidence supporting records before broadening pivots."
        return " ".join(part for part in (headline, " ".join(findings[:2]), action_hint) if part)
    if "uncertainty" in intents and uncertainty:
        return " ".join(part for part in (headline, " ".join(findings[:2]), f"Main limit: {uncertainty[0]}") if part)
    if "summary" in intents:
        return " ".join(part for part in (headline, findings[0] if findings else "", findings[1] if len(findings) > 1 else "") if part)
    if "open_analysis" in intents:
        return " ".join(part for part in (headline, findings[0] if findings else "") if part)
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


def _is_blocked_webhook_host(hostname: str) -> bool:
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host or host in {"localhost", "localhost.localdomain"}:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return any(
        (
            ip.is_loopback,
            ip.is_private,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def _webhook_host_resolves_safely(hostname: str) -> bool:
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        addrinfo = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)

    resolved_ips = {item[4][0] for item in addrinfo if item and item[4]}
    return bool(resolved_ips) and all(not _is_blocked_webhook_host(ip) for ip in resolved_ips)


def _validated_n8n_webhook_url() -> str:
    url = _n8n_webhook_url()
    parsed = urlparse(url)
    hostname = str(parsed.hostname or "").lower()
    allowed_hosts = {str(host).strip().lower() for host in getattr(settings, "INTEL_ALLOWED_WEBHOOK_HOSTS", []) if str(host).strip()}
    allow_local = bool(getattr(settings, "INTEL_CHAT_N8N_ALLOW_LOCAL", False))
    is_local = hostname in {"localhost", "localhost.localdomain"} or _hostname_is_private_or_loopback(hostname)

    if not hostname or parsed.scheme not in {"http", "https"}:
        raise ChatbotServiceError("n8n webhook URL must use HTTP or HTTPS.")
    if is_local:
        if not allow_local:
            raise ChatbotServiceError("Local n8n webhook hosts are not enabled.")
    elif parsed.scheme != "https":
        raise ChatbotServiceError("Remote n8n webhook URL must use HTTPS.")
    elif _is_blocked_webhook_host(hostname):
        raise ChatbotServiceError("n8n webhook host is not allowed.")
    elif not allowed_hosts and not _webhook_host_resolves_safely(hostname):
        raise ChatbotServiceError("n8n webhook host resolution is not allowed.")

    if allowed_hosts and hostname not in allowed_hosts:
        raise ChatbotServiceError("n8n webhook host is not in the allowlist.")
    return url


def _build_n8n_payload(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized = {
        "request_id": payload.get("request_id"),
        "workflow": {
            "name": "threatfoundry_analyst_chat",
            "contract_version": "2026-04-analyst-chat-v1",
            "response_contract": N8N_RESPONSE_CONTRACT,
        },
        "analyst_question": payload.get("analyst_question") or payload.get("user_query"),
        "user_query": payload.get("user_query"),
        "summary_mode": payload.get("summary_mode"),
        "response_guidance": payload.get("response_guidance") or {},
        "conversation_context": payload.get("conversation_context") or [],
        "dashboard_filters": payload.get("dashboard_filters"),
        "context": {
            "ioc": payload.get("ioc_context"),
            "filters": payload.get("dashboard_filters"),
        },
        "ioc_context": payload.get("ioc_context"),
    }
    if getattr(settings, "INTEL_CHAT_INCLUDE_SYSTEM_PROMPT", False):
        sanitized["system_instructions"] = payload.get("system_instructions") or payload.get("system_prompt")

    context = sanitized["context"].get("ioc")
    if isinstance(context, dict):
        context = dict(context)
        context["focused_records"] = list(context.get("focused_records") or [])[:8]
        context["top_suspicious"] = list(context.get("top_suspicious") or [])[:10]
        context["noisy_records"] = list(context.get("noisy_records") or [])[:10]
        lookup = context.get("lookup")
        if isinstance(lookup, dict):
            lookup = dict(lookup)
            lookup["results"] = list(lookup.get("results") or [])[:5]
            context["lookup"] = lookup
        sanitized["context"]["ioc"] = context
        sanitized["ioc_context"] = context
    return sanitized


def _hostname_is_private_or_loopback(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


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
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, list):
        return []
    rows = []
    for item in value:
        if isinstance(item, Mapping):
            text = str(item.get("text") or item.get("value") or item.get("content") or "").strip()
        else:
            text = str(item).strip()
        if text:
            rows.append(text)
    return rows


def _dedupe_text(items: list[str]) -> list[str]:
    rows = []
    seen = set()
    for item in items:
        text = str(item or "").strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            rows.append(text)
    return rows


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
                    "correlation_reasons": _normalize_text_list(item.get("correlation_reasons")),
                    "enrichment_providers": _normalize_text_list(item.get("enrichment_providers")),
                    "enrichment_count": int(item.get("enrichment_count") or 0),
                    "calculated_score": item.get("calculated_score"),
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
