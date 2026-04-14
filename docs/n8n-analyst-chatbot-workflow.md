# n8n Analyst Chatbot Workflow (Local n8n + Ollama)

This workflow uses a real model call and grounded ThreatFoundry context.

## Architecture

The workflow now runs this sequence:

1. Webhook receives analyst request
2. Parse `user_query` / `summary_mode` / `dashboard_filters`
3. Call ThreatFoundry context API (`/api/assistant/context/`)
4. Build a strict grounded prompt from returned IOC context
5. Call Ollama (`/api/generate`)
6. Extract model answer
7. Return structured JSON response

## Required services

- n8n (Docker): `http://localhost:5678`
- ThreatFoundry app: reachable from n8n container, typically `http://host.docker.internal:8080`
- Ollama host service: reachable from n8n container, typically `http://host.docker.internal:11434`

## 1. Configure env vars in ThreatFoundry

```env
INTEL_CHAT_PROVIDER=n8n
INTEL_CHAT_N8N_WEBHOOK_URL=http://localhost:5678/webhook/threatfoundry-analyst-chat
INTEL_CHAT_N8N_TIMEOUT=20
INTEL_CHAT_N8N_BEARER_TOKEN=
INTEL_CHAT_CONTEXT_API_TOKEN=replace-with-a-long-random-token
```

`INTEL_CHAT_CONTEXT_API_TOKEN` is used by n8n when it requests IOC context from ThreatFoundry.

## 2. Configure env vars in n8n container

Set these in n8n (container env or workflow-level env):

```env
THREATFOUNDRY_CONTEXT_URL=http://host.docker.internal:8080/api/assistant/context/
INTEL_CHAT_CONTEXT_API_TOKEN=replace-with-the-same-token-as-threatfoundry
OLLAMA_API_URL=http://host.docker.internal:11434/api/generate
OLLAMA_MODEL=llama3.1:8b
```

## 3. Create/update workflow in n8n

```powershell
$env:N8N_API_KEY = "replace-with-your-key"
.\n8n\create_n8n_analyst_workflow.ps1 -BaseUrl "http://localhost:5678" -Activate
```

## Request/response contract

ThreatFoundry -> n8n webhook payload:

- `user_query`
- `summary_mode`
- `dashboard_filters`

n8n -> ThreatFoundry context API payload:

- `prompt`
- `summary_mode`
- `dashboard_filters`

n8n webhook response payload:

- `answer` (required)
- `key_findings` (list)
- `recommended_actions` (list)
- `uncertainty` (list)
- `supporting_records` (list)
- `provider`
- `source_of_truth`

If no relevant ThreatFoundry data exists for the scope/targets, workflow returns a clear no-data answer instead of generating unsupported claims.
