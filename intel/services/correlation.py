from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlparse

from django.db.models import Q
from django.utils import timezone

from intel.models import IntelIOC


HASH_TYPE_ALIASES = {
    "md5": {"FileHash-MD5", "md5_hash"},
    "sha1": {"FileHash-SHA1", "sha1_hash"},
    "sha256": {"FileHash-SHA256", "sha256_hash"},
}
UNKNOWN_VALUES = {"", "unknown", "not provided", "n/a", "none", "null"}
CORRELATION_PROMOTION_THRESHOLD = 60
RECENT_CORRELATION_WINDOW = timedelta(days=7)

FAMILY_ALIAS_OVERRIDES = {
    "clear fake": "clearfake",
    "clear_fake": "clearfake",
    "async rat": "asyncrat",
    "async_rat": "asyncrat",
    "smoke loader": "smokeloader",
    "smoke_loader": "smokeloader",
    "agent tesla": "agenttesla",
    "agent_tesla": "agenttesla",
}


@dataclass(frozen=True)
class CorrelationAnalysis:
    score: int
    exact_multi_source: bool
    family_agreement: bool
    tag_overlap: bool
    time_correlation: bool
    enrichment_agreement: bool
    conflicting_families: bool
    top_family: str
    top_threat_type: str
    family_counts: Counter[str]
    family_display: dict[str, str]
    exact_match_count: int
    recent_match_count: int
    overlap_tags: list[str]
    matched_sources: list[str]


def canonical_hash_type(value_type: str | None) -> str | None:
    text = str(value_type or "").strip()
    for canonical, aliases in HASH_TYPE_ALIASES.items():
        if text in aliases:
            return canonical
    return None


def normalize_family_alias(name: str) -> str:
    text = str(name or "").strip().lower()
    if not text:
        return ""

    collapsed = " ".join(text.replace("_", " ").replace("-", " ").split())
    collapsed = FAMILY_ALIAS_OVERRIDES.get(collapsed, collapsed)
    return "".join(char for char in collapsed if char.isalnum())


def score_ioc_correlation(record, candidate_records) -> int:
    return _analyze_correlation(record, list(candidate_records)).score


def build_correlation_reasons(record, matches) -> list[str]:
    analysis = _analyze_correlation(record, list(matches))
    reasons: list[str] = []

    if analysis.exact_multi_source:
        reasons.append(
            f"Exact IOC value/type match found across {analysis.exact_match_count} local record(s) from {len(analysis.matched_sources)} source(s)."
        )
    if analysis.family_agreement and analysis.top_family:
        reasons.append(
            f"Malware family signals converge on {analysis.top_family}."
        )
    if analysis.tag_overlap and analysis.overlap_tags:
        reasons.append(
            f"Shared tags support the correlation: {', '.join(analysis.overlap_tags[:5])}."
        )
    if analysis.time_correlation:
        reasons.append(
            f"{analysis.recent_match_count} correlated record(s) were observed within the last 7 days."
        )
    if analysis.enrichment_agreement and analysis.top_family:
        reasons.append(
            f"Stored enrichment payloads align with the {analysis.top_family} family inference."
        )
    if analysis.conflicting_families:
        reasons.append(
            "Conflicting malware-family hints reduced confidence, so the result was kept conservative."
        )
    if analysis.top_threat_type:
        reasons.append(f"Likely threat type inferred as {analysis.top_threat_type}.")
    if not reasons:
        reasons.append("No sufficiently strong local correlation signals were found.")
    return reasons


def correlate_unknown_iocs(limit: int | None = None) -> dict:
    queryset = _unknown_ioc_queryset().order_by("-last_ingested_at", "-created_at", "-id")
    if limit is not None:
        queryset = queryset[: max(limit, 0)]

    processed = 0
    skipped = 0
    promoted = 0
    results: list[dict] = []

    for record in queryset:
        processed += 1
        candidates = _find_candidate_records(record)
        analysis = _analyze_correlation(record, candidates)
        reasons = build_correlation_reasons(record, candidates)

        update_fields = {
            "derived_confidence_level": analysis.score or None,
            "correlation_reasons": reasons,
            "likely_threat_type": "",
            "likely_malware_family": "",
        }
        promoted_this_record = False

        if analysis.score >= CORRELATION_PROMOTION_THRESHOLD:
            if _is_unknown_text(record.threat_type) and analysis.top_threat_type:
                update_fields["likely_threat_type"] = analysis.top_threat_type
                promoted_this_record = True
            if _is_unknown_text(record.malware_family) and analysis.top_family:
                update_fields["likely_malware_family"] = analysis.top_family
                promoted_this_record = True

        if promoted_this_record:
            promoted += 1
        else:
            skipped += 1

        IntelIOC.objects.filter(pk=record.pk).update(**update_fields)
        results.append(
            {
                "pk": record.pk,
                "value": record.value,
                "value_type": record.value_type,
                "score": analysis.score,
                "promoted": promoted_this_record,
                "likely_threat_type": update_fields["likely_threat_type"],
                "likely_malware_family": update_fields["likely_malware_family"],
                "reasons": reasons,
            }
        )

    return {
        "processed": processed,
        "skipped": skipped,
        "promoted": promoted,
        "results": results,
    }


def build_hash_correlation_context(record: IntelIOC, limit: int = 10) -> dict:
    """
    Correlate a hash IOC against ThreatFox and summarize any malware-family hits.

    We only perform exact hash matching. If a source does not expose hash values
    in a compatible type, the UI should say so plainly instead of implying a
    fuzzy match or invented malware family.
    """
    canonical_type = canonical_hash_type(record.value_type)
    if canonical_type is None:
        return {
            "applicable": False,
            "title": "Hash correlation",
            "message": "This IOC is not stored as a hash, so ThreatFox hash correlation is not applicable.",
            "matches": [],
            "families": [],
            "threat_types": [],
            "canonical_type": "",
        }

    matching_types = HASH_TYPE_ALIASES[canonical_type]
    matches = list(
        IntelIOC.objects.filter(
            source_name="threatfox",
            value_type__in=matching_types,
            value__iexact=record.value,
        )
        .order_by("-last_ingested_at", "-created_at", "-id")[:limit]
    )

    family_counter: Counter[str] = Counter()
    threat_counter: Counter[str] = Counter()
    match_rows = []

    for match in matches:
        family = str(match.malware_family or "").strip()
        threat_type = str(match.threat_type or "").strip()
        if family:
            family_counter[family] += 1
        if threat_type:
            threat_counter[threat_type] += 1

        match_rows.append(
            {
                "pk": match.pk,
                "value": match.value,
                "value_type": match.value_type,
                "malware_family": family or "Not provided",
                "threat_type": threat_type or "Not provided",
                "reporter": str(match.reporter or "").strip() or "Not provided",
                "last_ingested_at": match.last_ingested_at,
            }
        )

    family_rows = [
        {"label": label, "count": count}
        for label, count in family_counter.most_common()
    ]
    threat_rows = [
        {"label": label, "count": count}
        for label, count in threat_counter.most_common()
    ]

    if matches:
        message = "ThreatFox contains exact hash matches for this IOC. Malware-family suggestions below are evidence-backed correlations."
    else:
        message = "No exact ThreatFox hash matches were found for this IOC in the current dataset."

    return {
        "applicable": True,
        "title": "ThreatFox hash correlation",
        "message": message,
        "matches": match_rows,
        "families": family_rows,
        "threat_types": threat_rows,
        "canonical_type": canonical_type.upper(),
    }


def _unknown_ioc_queryset():
    return IntelIOC.objects.filter(
        Q(threat_type__isnull=True)
        | Q(threat_type="")
        | Q(threat_type__iexact="unknown")
        | Q(malware_family__isnull=True)
        | Q(malware_family="")
        | Q(malware_family__iexact="unknown")
        | Q(confidence_level__isnull=True)
        | (
            Q(enrichment_payloads__isnull=False)
            & ~Q(enrichment_payloads={})
            & (
                Q(threat_type__isnull=True)
                | Q(threat_type="")
                | Q(threat_type__iexact="unknown")
                | Q(malware_family__isnull=True)
                | Q(malware_family="")
                | Q(malware_family__iexact="unknown")
            )
        )
    )


def _find_candidate_records(record: IntelIOC) -> list[IntelIOC]:
    query = Q(value__iexact=record.value, value_type__iexact=record.value_type)
    host = _extract_host(record.value, record.value_type)
    path_prefix = _extract_path_prefix(record.value, record.value_type)

    if host:
        query |= Q(value__iexact=host, value_type__in=["domain", "hostname"])
        query |= Q(value_type="url", value__icontains=host)
    if path_prefix:
        query |= Q(value_type="url", value__icontains=path_prefix)

    return list(
        IntelIOC.objects.exclude(pk=record.pk)
        .filter(query)
        .order_by("-last_seen", "-last_ingested_at", "-created_at", "-id")[:100]
    )


def _analyze_correlation(record: IntelIOC, candidate_records: list[IntelIOC]) -> CorrelationAnalysis:
    exact_matches = [
        candidate
        for candidate in candidate_records
        if str(candidate.value or "").strip().lower() == str(record.value or "").strip().lower()
        and str(candidate.value_type or "").strip().lower() == str(record.value_type or "").strip().lower()
    ]
    matched_sources = sorted({record.source_name, *(candidate.source_name for candidate in exact_matches)})
    exact_multi_source = len(exact_matches) > 0 and len(matched_sources) >= 2

    family_counts: Counter[str] = Counter()
    family_display: dict[str, str] = {}
    enrichment_family_counts: Counter[str] = Counter()
    threat_counts: Counter[str] = Counter()
    overlap_tags: set[str] = set()
    reporter_overlap = False
    recent_match_count = 0

    record_tags = {tag.lower() for tag in _normalize_tags(record.tags)}
    record_reporter = str(record.reporter or "").strip().lower()
    reference_observed_at = _observed_at(record)
    record_enrichment_hints = _extract_enrichment_family_hints(record)

    for candidate in candidate_records:
        candidate_families = _extract_family_hints(candidate)
        for display_name in candidate_families:
            alias = normalize_family_alias(display_name)
            if not alias:
                continue
            family_counts[alias] += 1
            family_display.setdefault(alias, display_name)

        candidate_enrichment_hints = _extract_enrichment_family_hints(candidate)
        for display_name in candidate_enrichment_hints:
            alias = normalize_family_alias(display_name)
            if not alias:
                continue
            enrichment_family_counts[alias] += 1
            family_display.setdefault(alias, display_name)

        for threat_type in _extract_threat_hints(candidate):
            threat_counts[threat_type] += 1

        candidate_tags = {tag.lower() for tag in _normalize_tags(candidate.tags)}
        overlap_tags.update(record_tags & candidate_tags)

        candidate_reporter = str(candidate.reporter or "").strip().lower()
        if record_reporter and candidate_reporter and record_reporter == candidate_reporter:
            reporter_overlap = True

        candidate_observed_at = _observed_at(candidate)
        if (
            reference_observed_at is not None
            and candidate_observed_at is not None
            and abs(reference_observed_at - candidate_observed_at) <= RECENT_CORRELATION_WINDOW
        ):
            recent_match_count += 1

    top_family_alias = ""
    if family_counts:
        top_family_alias = family_counts.most_common(1)[0][0]

    top_threat_type = threat_counts.most_common(1)[0][0] if threat_counts else ""

    family_agreement = bool(
        top_family_alias
        and (
            family_counts[top_family_alias] >= 2
            or (family_counts[top_family_alias] >= 1 and exact_multi_source)
        )
    )
    record_enrichment_matches = any(
        normalize_family_alias(hint) == top_family_alias for hint in record_enrichment_hints
    )
    enrichment_agreement = bool(
        top_family_alias
        and (
            enrichment_family_counts[top_family_alias] >= 1
            or record_enrichment_matches
        )
    )
    tag_overlap = bool(overlap_tags or reporter_overlap)
    time_correlation = recent_match_count > 0
    conflicting_families = len([alias for alias, count in family_counts.items() if count > 0]) > 1

    score = 0
    if exact_multi_source:
        score += 30
    if family_agreement:
        score += 25
    if tag_overlap:
        score += 15
    if time_correlation:
        score += 15
    if enrichment_agreement:
        score += 15
    if conflicting_families:
        score -= 20
    score = max(0, min(score, 100))

    return CorrelationAnalysis(
        score=score,
        exact_multi_source=exact_multi_source,
        family_agreement=family_agreement,
        tag_overlap=tag_overlap,
        time_correlation=time_correlation,
        enrichment_agreement=enrichment_agreement,
        conflicting_families=conflicting_families,
        top_family=family_display.get(top_family_alias, ""),
        top_threat_type=top_threat_type,
        family_counts=family_counts,
        family_display=family_display,
        exact_match_count=len(exact_matches),
        recent_match_count=recent_match_count,
        overlap_tags=sorted(overlap_tags),
        matched_sources=matched_sources,
    )


def _extract_family_hints(record: IntelIOC) -> list[str]:
    hints: list[str] = []

    if not _is_unknown_text(record.malware_family):
        hints.append(str(record.malware_family).strip())

    raw_payload = record.raw_payload if isinstance(record.raw_payload, dict) else {}
    for candidate in (
        raw_payload.get("signature"),
        raw_payload.get("malware"),
        raw_payload.get("malware_printable"),
    ):
        text = str(candidate or "").strip()
        if text and not _is_unknown_text(text):
            hints.append(text)

    hints.extend(_extract_enrichment_family_hints(record))
    return _dedupe_texts(hints)


def _extract_enrichment_family_hints(record: IntelIOC) -> list[str]:
    payloads = record.enrichment_payloads if isinstance(record.enrichment_payloads, dict) else {}
    hints: list[str] = []

    for payload in payloads.values():
        if not isinstance(payload, dict):
            continue
        summary = payload.get("summary")
        if not isinstance(summary, dict):
            continue

        hints.extend(_extract_ranked_labels(summary.get("popular_threat_names")))
        hints.extend(_extract_ranked_labels(summary.get("sandbox_malware_names")))

    return _dedupe_texts(hints)


def _extract_threat_hints(record: IntelIOC) -> list[str]:
    hints: list[str] = []

    if not _is_unknown_text(record.threat_type):
        hints.append(str(record.threat_type).strip())

    raw_payload = record.raw_payload if isinstance(record.raw_payload, dict) else {}
    for candidate in (raw_payload.get("threat"), raw_payload.get("url_status")):
        text = str(candidate or "").strip()
        if text and not _is_unknown_text(text):
            hints.append(text)

    payloads = record.enrichment_payloads if isinstance(record.enrichment_payloads, dict) else {}
    for payload in payloads.values():
        if not isinstance(payload, dict):
            continue
        summary = payload.get("summary")
        if not isinstance(summary, dict):
            continue
        for candidate in (
            summary.get("popular_threat_label"),
            *_extract_ranked_labels(summary.get("popular_threat_categories")),
        ):
            text = str(candidate or "").strip()
            if text and not _is_unknown_text(text):
                hints.append(text)

    return _dedupe_texts(hints)


def _extract_ranked_labels(values) -> list[str]:
    if not isinstance(values, list):
        return []

    labels: list[str] = []
    for item in values:
        if isinstance(item, dict):
            text = str(item.get("label") or item.get("value") or "").strip()
        else:
            text = str(item or "").strip()
        if text and not _is_unknown_text(text):
            labels.append(text)
    return labels


def _dedupe_texts(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(value.strip())
    return result


def _normalize_tags(tags) -> list[str]:
    if isinstance(tags, str):
        tags = [tags]

    return [str(tag).strip() for tag in (tags or []) if str(tag).strip()]


def _observed_at(record: IntelIOC):
    return record.last_seen or record.first_seen or record.last_ingested_at or record.created_at


def _extract_host(value: str, value_type: str) -> str:
    text = str(value or "").strip()
    normalized_type = str(value_type or "").strip().lower()
    if not text:
        return ""
    if normalized_type in {"domain", "hostname"}:
        return text.lower()
    if normalized_type == "url":
        return (urlparse(text).hostname or "").lower()
    return ""


def _extract_path_prefix(value: str, value_type: str) -> str:
    if str(value_type or "").strip().lower() != "url":
        return ""

    parsed = urlparse(str(value or "").strip())
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    if not hostname:
        return ""

    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return hostname
    return f"{hostname}/{'/'.join(segments[:2])}"


def _is_unknown_text(value) -> bool:
    return str(value or "").strip().lower() in UNKNOWN_VALUES
