from collections import Counter

from django.utils import timezone
from django.template.loader import render_to_string


UNKNOWN_FAMILY_VALUES = {"", "unknown", "not provided", "n/a", "none", "null"}


def _pick_value(source, key, default=None):
    if isinstance(source, dict):
        return source.get(key, default)
    return getattr(source, key, default)


def _source_labels_for_row(row) -> list[str]:
    if isinstance(row, dict):
        badges = row.get("source_badges") or []
        if badges:
            return [str(badge).strip() for badge in badges if str(badge).strip()]

        record = row.get("record")
        source_name = getattr(record, "source_name", "")
        if source_name:
            return [str(source_name).strip()]
        return []

    source_name = getattr(row, "source", "")
    if source_name:
        return [str(source_name).strip()]
    return []


def _meaningful_family_label(value) -> str:
    text = str(value or "").strip()
    if text.lower() in UNKNOWN_FAMILY_VALUES:
        return ""
    return text


def _family_counts_from_distribution(malware_distribution) -> Counter:
    counts = Counter()
    if not isinstance(malware_distribution, dict):
        return counts

    labels = malware_distribution.get("labels") or []
    values = malware_distribution.get("values") or []
    for label, value in zip(labels, values):
        family = _meaningful_family_label(label)
        if not family:
            continue
        try:
            count = int(value or 0)
        except (TypeError, ValueError):
            count = 0
        if count > 0:
            counts[family] += count
    return counts


def _family_counts_from_rows(recent_ioc_rows) -> Counter:
    counts = Counter()
    for row in recent_ioc_rows or []:
        family = ""
        if isinstance(row, dict):
            family = _meaningful_family_label(row.get("malware_family"))
            if not family:
                record = row.get("record")
                family = _meaningful_family_label(
                    getattr(record, "malware_family", "")
                    or getattr(record, "likely_malware_family", "")
                )
        else:
            family = _meaningful_family_label(
                getattr(row, "malware_family", "")
                or getattr(row, "likely_malware_family", "")
            )
        if family:
            counts[family] += 1
    return counts


def build_malware_attribution(malware_distribution=None, recent_ioc_rows=None) -> dict:
    family_counts = _family_counts_from_distribution(malware_distribution)
    if not family_counts:
        family_counts = _family_counts_from_rows(recent_ioc_rows)

    families = [
        {"label": label, "count": count}
        for label, count in family_counts.most_common(5)
    ]
    total_attributed = sum(family_counts.values())
    if not families:
        return {
            "has_attribution": False,
            "dominant_family": "",
            "dominant_count": 0,
            "total_attributed": 0,
            "families_observed": [],
            "summary": "No malware family attribution is available in the current report scope.",
        }

    dominant = families[0]
    dominant_share = dominant["count"] / total_attributed if total_attributed else 0
    has_multiple = len(family_counts) > 1

    if not has_multiple:
        summary = (
            f"Scoped IOC activity is attributable to {dominant['label']} "
            f"across {dominant['count']} record{'s' if dominant['count'] != 1 else ''}."
        )
    elif dominant_share >= 0.6:
        summary = (
            f"{dominant['label']} is the dominant malware family in scope, "
            f"representing {dominant['count']} of {total_attributed} attributed records."
        )
    else:
        summary = (
            "Multiple malware families are present in the current scope; "
            f"{dominant['label']} is the largest observed family but attribution is mixed."
        )

    return {
        "has_attribution": True,
        "dominant_family": dominant["label"],
        "dominant_count": dominant["count"],
        "total_attributed": total_attributed,
        "families_observed": families,
        "summary": summary,
    }


def generate_exec_report(kpis, ioc_blades, recent_ioc_rows, malware_distribution=None):
    source_counts = Counter()
    for row in (recent_ioc_rows or []):
        for label in _source_labels_for_row(row):
            source_counts[label] += 1

    top_blades = list(ioc_blades or [])[:5]
    malware_attribution = build_malware_attribution(
        malware_distribution=malware_distribution,
        recent_ioc_rows=recent_ioc_rows,
    )
    report = {
        "generated_at": timezone.now(),
        "total_iocs": _pick_value(kpis, "total_iocs", 0) or 0,
        "average_confidence": _pick_value(kpis, "average_confidence"),
        "malware_attribution": malware_attribution,
        "top_severity_indicators": top_blades,
        "most_active_sources": [
            {"label": label, "count": count}
            for label, count in source_counts.most_common(5)
        ],
        "anomaly_summary": (
            "Multiple repeated indicators are present in the current dashboard scope."
            if any((blade.get("record_count") or 0) > 1 for blade in top_blades)
            else "No repeated IOC concentration detected in the current scope."
        ),
        "notable_trends": (
            f"Confidence is elevated across scoped records. {malware_attribution['summary']}"
            if (_pick_value(kpis, "average_confidence") or 0) >= 70
            else f"Confidence distribution appears mixed in the current scope. {malware_attribution['summary']}"
        ),
    }

    html_report = render_to_string("intel/executive_report.html", {"report": report})
    markdown_report = render_to_string("intel/executive_report.md", {"report": report})

    return {
        "html": html_report,
        "markdown": markdown_report,
    }
