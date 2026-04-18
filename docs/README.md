# ThreatFoundry Documentation

This documentation set describes the current implementation of ThreatFoundry in this repository.

## Documentation Map

- [Application Summary](application-summary.md): Product overview, scope, and quick start.
- [Feature Reference](feature-reference.md): End-to-end feature inventory for UI, CLI, ingestion, enrichment, and run tracking.
- [Architecture Reference](architecture-reference.md): Data model, service boundaries, request/data flow, and provider integration internals.
- [Ticket Workspace](ticket-workspace.md): Analyst ticketing, notes, workspace tabs, popout behavior, and security notes.
- [Analyst Chat n8n Contract](analyst_chat_n8n_contract.md): Payload and response contract for local n8n assistant integration.
- [n8n Analyst Chatbot Workflow](n8n-analyst-chatbot-workflow.md): Operational notes for the n8n-backed analyst assistant workflow.
- [MCP Server Reference](mcp-server-reference.md): Reference for local MCP/server integration notes.
- [Operations Runbook](operations-runbook.md): Day-to-day commands, refresh scheduling, environment configuration, and troubleshooting.

## What Is Included

- Multi-source IOC ingestion: ThreatFox, AlienVault OTX, URLHaus.
- IOC enrichment: VirusTotal.
- Provider capability model and availability/status checks.
- Analyst web UI: dashboard, IOC detail, IOC blade detail, malware directory/family pages.
- Analyst assistant with local, n8n, and hybrid response modes.
- Analyst ticket workspace with notes, tabs, and popout detail views.
- Documentation wiki route with dynamic markdown page loading.
- Time-display preference (local 12-hour, local 24-hour, UTC 24-hour).
- Operational run tracking via `ProviderRun`, `IngestionRun`, and `ProviderRunDetail`.

## Quick Start

```bash
python -m pip install -r requirements.txt
# Linux/macOS: cp .env.example .env
# Windows (PowerShell): Copy-Item .env.example .env
python manage.py migrate
python manage.py populate_sample_iocs
python manage.py runserver
```

Open `http://127.0.0.1:8080/`.

## Notes

- The docs route in the app (`/docs/`) renders every `*.md` file in this `docs/` directory.
- If you add a new markdown file here, it will automatically appear in the in-app documentation sidebar.
- Documentation markdown is escaped before conversion, so docs should use normal Markdown rather than raw HTML.
