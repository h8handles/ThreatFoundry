from django.conf import settings
from django.template.loader import render_to_string

def generate_exec_report(kpis, ioc_blades, recent_ioc_rows):
    report = {
        "total_iocs": kpis.total_iocs,
        "top_severity_indicators": ioc_blades[:5],
        "most_active_sources": [row.source for row in recent_ioc_rows[:3]],
        "anomaly_summary": "Anomaly summary goes here",
        "average_confidence": kpis.average_confidence,
        "notable_trends": "Notable trends go here"
    }

    # Render the report as HTML
    html_report = render_to_string("intel/executive_report.html", {"report": report})

    # Optionally, render the report as Markdown
    markdown_report = render_to_string("intel/executive_report.md", {"report": report})

    return {
        "html": html_report,
        "markdown": markdown_report
    }
