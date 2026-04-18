# Analyst Chat n8n Contract

ThreatFoundry sends analyst chat requests to the configured n8n webhook when
`INTEL_CHAT_PROVIDER` is `hybrid` or `n8n` and `INTEL_CHAT_N8N_WEBHOOK_URL` is set.
Hybrid mode falls back to the local database answer if the workflow is unreachable
or returns an invalid response.

## Request Shape

```json
{
  "request_id": "generated-hex-id",
  "workflow": {
    "name": "threatfoundry_analyst_chat",
    "contract_version": "2026-04-analyst-chat-v1",
    "response_contract": {
      "answer": "Required natural-language answer. n8n may also return summary.",
      "reasoning_summary": "Optional short explanation of how the answer was derived.",
      "confidence": "Optional confidence label or score.",
      "key_findings": "Optional list of supporting findings.",
      "recommended_actions": "Optional list of next investigative actions.",
      "uncertainty": "Optional list of limits or unknowns.",
      "supporting_records": "Optional list of cited IOC records.",
      "cited_iocs": "Optional alternate field for cited IOC records."
    }
  },
  "analyst_question": "What should I investigate first?",
  "user_query": "What should I investigate first?",
  "summary_mode": "auto|analyst|technical|executive|brief",
  "conversation_context": [
    {"role": "user", "content": "Previous analyst question"},
    {"role": "assistant", "content": "Previous answer"}
  ],
  "dashboard_filters": {
    "start_date": "",
    "end_date": "",
    "value_type": "",
    "malware_family": "",
    "threat_type": "",
    "confidence_band": "",
    "search": "",
    "tag": "",
    "sort": "ingested",
    "direction": "desc",
    "page_size": 25
  },
  "context": {
    "filters": {},
    "ioc": {
      "query_focus": {"intents": ["prioritization"], "prefers_actions": true},
      "metrics": {},
      "lookup": {},
      "focused_records": [],
      "top_suspicious": [],
      "source_breakdown": [],
      "cluster_breakdown": [],
      "threat_breakdown": [],
      "confidence_overview": {},
      "daily_counts": [],
      "enrichment_summary": {}
    }
  },
  "ioc_context": {}
}
```

`ioc_context` is retained as a compatibility alias for existing workflow nodes.
New workflow nodes should prefer `context.ioc`.

## Response Shape

The workflow must return JSON with an `answer` or `summary` field. It may return
the payload directly, under `response`, as an n8n `json` object, or as the first
item in an n8n item array.

```json
{
  "answer": "Natural analyst answer",
  "reasoning_summary": "Optional concise reasoning summary",
  "confidence": "medium-high",
  "key_findings": ["Finding"],
  "recommended_actions": ["Next step"],
  "uncertainty": ["Known gap"],
  "supporting_records": [],
  "provider": "n8n",
  "source_of_truth": "database+n8n"
}
```

Supported alternate fields include `summary`, `suggested_next_actions`,
`next_actions`, `cited_iocs`, and `citations`.
