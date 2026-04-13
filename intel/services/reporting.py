from collections import Counter

from django.utils import timezone
from django.template.loader import render_to_string


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


def generate_exec_report(kpis, ioc_blades, recent_ioc_rows):
    source_counts = Counter()
    for row in (recent_ioc_rows or []):
        for label in _source_labels_for_row(row):
            source_counts[label] += 1

    top_blades = list(ioc_blades or [])[:5]
    report = {
        "generated_at": timezone.now(),
        "total_iocs": _pick_value(kpis, "total_iocs", 0) or 0,
        "average_confidence": _pick_value(kpis, "average_confidence"),
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
            "Confidence is elevated across scoped records."
            if (_pick_value(kpis, "average_confidence") or 0) >= 70
            else "Confidence distribution appears mixed in the current scope."
        ),
    }

    html_report = render_to_string("intel/executive_report.html", {"report": report})
    markdown_report = render_to_string("intel/executive_report.md", {"report": report})

    return {
        "html": html_report,
        "markdown": markdown_report,
    }
