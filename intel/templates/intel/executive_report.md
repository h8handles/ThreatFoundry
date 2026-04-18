# Executive Threat Report

Generated: {{ report.generated_at }}

## Key Metrics

- Total IOCs: {{ report.total_iocs }}
- Average Confidence: {% if report.average_confidence is not None %}{{ report.average_confidence|floatformat:1 }}{% else %}N/A{% endif %}

## Malware Family Attribution

{{ report.malware_attribution.summary }}

{% if report.malware_attribution.has_attribution %}
- Dominant Malware Family: {{ report.malware_attribution.dominant_family }} ({{ report.malware_attribution.dominant_count }})
- Total Attributed Records: {{ report.malware_attribution.total_attributed }}

| Family | Records |
|---|---:|
{% for family in report.malware_attribution.families_observed %}
| {{ family.label }} | {{ family.count }} |
{% endfor %}
{% endif %}

## Top Indicators

{% if report.top_severity_indicators %}
| Indicator | Type | Records | Sources |
|---|---|---:|---|
{% for item in report.top_severity_indicators %}
| {{ item.value }} | {{ item.type_label }} | {{ item.record_count }} | {{ item.source_summary }} |
{% endfor %}
{% else %}
No indicators in current scope.
{% endif %}

## Most Active Sources

{% if report.most_active_sources %}
{% for source in report.most_active_sources %}
- {{ source.label }}: {{ source.count }}
{% endfor %}
{% else %}
No source activity in current scope.
{% endif %}

## Summary

- Anomaly Summary: {{ report.anomaly_summary }}
- Notable Trends: {{ report.notable_trends }}
