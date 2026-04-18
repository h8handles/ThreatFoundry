# Application Summary

## One-Sentence Summary

ThreatFoundry is a Django threat-intelligence console that ingests, normalizes, enriches, tracks, and visualizes indicators of compromise (IOCs) from multiple providers, with analyst assistant and ticket workspace flows for investigation work.

## Product Scope (Current Implementation)

### Core Goals

- Collect IOC data from free/community provider feeds.
- Normalize heterogeneous payloads into one queryable IOC model.
- Preserve full source payloads for analyst review and future schema evolution.
- Provide analyst workflows in both web UI and CLI.
- Provide analyst ticketing and note-taking for investigation follow-up.
- Track ingestion/enrichment run outcomes for operational visibility.

### Supported Data Flows

- Ingestion providers:
  - ThreatFox
  - AlienVault OTX
  - URLHaus
- Enrichment provider:
  - VirusTotal

### Delivery Surfaces

- Server-rendered Django web UI.
- Django admin.
- Django management commands (CLI workflows).

## User-Facing Web Experience

### Primary Routes

- `/` and `/dashboard/`: main dashboard.
- `/malware/`: malware family directory, and family detail via query parameter.
- `/ioc/<pk>/`: IOC detail.
- `/ioc-blade/?value=...&value_type=...`: aggregated IOC blade detail.
- `/assistant/`: analyst assistant.
- `/tickets/`: analyst ticket workspace.
- `/tickets/<pk>/`: ticket detail workspace.
- `/docs/` and `/docs/<doc_name>/`: in-app markdown documentation wiki.
- `/admin/`: Django admin.

### Dashboard Capabilities

- Filters:
  - IOC search text.
  - Tag search text.
  - Date range (`start_date`, `end_date`).
  - IOC type.
  - Malware family.
  - Threat type.
  - Confidence band.
- Sorting:
  - By value, type, source, confidence, threat, observed time, or ingested time.
  - Ascending/descending direction.
- Pagination:
  - Page navigation and selectable page size (10/25/50/100).
- Visuals:
  - IOC timeline.
  - IOC type distribution.
  - Confidence distribution.
  - Malware-family distribution.
- Context panels:
  - Top tags.
  - Threat-type snapshot.
  - Provider readiness (enabled/not available).
- Search-specific aggregation:
  - IOC blades (one blade per unique IOC value+type across sources).

### IOC Detail Capabilities

- Overview cards for normalized IOC fields.
- Source-specific section rendering.
- Hash correlation section (exact-match ThreatFox correlation for hash IOC types).
- VirusTotal enrichment section when available.
- External reference grouping by provider.
- Raw payload panel with bounded scroll.

### Malware Workspace Capabilities

- Family directory cards.
- Family drill-down page with:
  - Family KPIs.
  - Activity chart.
  - Type/source distributions.
  - Traits, tags, references, and threat snapshot.
  - Paginated related IOC table.

### Documentation Wiki Capabilities

- Reads markdown files from `docs/`.
- Sidebar navigation generated from `*.md` files.
- AJAX navigation for page loads with browser-history support.

### Ticket Workspace Capabilities

- Ticket list and creation workspace for analyst users.
- Ticket detail workspace with editable status, priority, assignment, title, and description.
- Ticket notes displayed as an activity feed.
- Popout detail/workspace mode that reuses the authenticated Django session.
- Client-side workspace tabs persist only minimal UI metadata, not note content or tokens.

### Time Display Preferences

- Session-backed time display mode switch:
  - Friendly local (12-hour).
  - Local (24-hour).
  - UTC (24-hour, explicit UTC suffix).

## CLI and Automation Scope

### Ingestion Commands

- `import_threatfox --days N`
- `import_alienvault --days N`
- `import_urlhaus [--timeout SECONDS]`

### Enrichment Command

- `import_virustotal` with filter and runtime controls:
  - `--limit`
  - `--source` (repeatable)
  - `--value-type` (repeatable)
  - `--force`
  - `--timeout`
  - `--throttle-seconds`

### Orchestrated Refresh

- `refresh_intel` orchestrates enabled providers and records run outcomes.
- Supports:
  - `--provider`
  - `--timeout`
  - `--since` (relative like `24h`, `7d`, or ISO datetime)
  - `--dry-run`
  - `--no-feed-refresh`

### Analyst Utility Commands

- `domain_search <query> [--limit N] [--exact]`
- `print_ioc_stats`
- `print_latest_ioc`
- `populate_sample_iocs [--reset-samples]`

### Dev Server Behavior

- Custom runserver command defaults to `0.0.0.0:8080` unless address/port is provided.

## Data and Persistence

### Core Models

- `IntelIOC`: normalized IOC + raw payload + enrichment payloads.
- `ProviderRun`: per-command provider execution record.
- `IngestionRun`: top-level refresh run summary.
- `ProviderRunDetail`: per-provider detail rows attached to an `IngestionRun`.
- `Ticket`: analyst-created investigation ticket.
- `TicketNote`: chronological notes attached to a ticket.

### Storage Modes

- Default SQLite (`db.sqlite3`).
- Optional PostgreSQL when `POSTGRES_DB` is set.

## Provider Capability Model

Provider metadata is centralized in the provider registry.

### Implemented and Active-by-Configuration Providers

- Ingestion/enrichment logic implemented:
  - ThreatFox
  - AlienVault OTX
  - URLHaus
  - VirusTotal

### Registry-Only/Placeholder Providers

- AbuseIPDB
- Shodan
- CISA KEV
- CVE feed
- NVD
- MITRE ATT&CK
- Threat actor mapping

These may appear in provider readiness and link-generation capability logic, even when full ingestion/enrichment pipeline code is not wired for daily refresh execution.

## Environment Configuration Highlights

- Django settings: secret key, debug, hosts, CSRF, timezone.
- Provider API keys and toggles:
  - `THREATFOX_API_KEY`, `OTX_API_KEY`, `URLHAUS_API_KEY`, `VIRUSTOTAL_API_KEY`
  - Optional: `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `NVD_API_KEY`
  - Enable flags: `<PROVIDER>_ENABLED`
- Refresh controls:
  - `INTEL_REFRESH_SCHEDULE`
  - `INTEL_REFRESH_DEFAULT_SINCE`
  - `INTEL_REFRESH_TIMEOUT`
  - `INTEL_REFRESH_VIRUSTOTAL_LIMIT`
  - `INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS`

## Quick Start

```bash
python -m pip install -r requirements.txt
copy .env.example .env
python manage.py migrate
python manage.py populate_sample_iocs
python manage.py runserver
```

Open `http://127.0.0.1:8080/`.

## Validation Commands

```bash
python manage.py check
python manage.py print_ioc_stats
python manage.py refresh_intel --dry-run
python manage.py test intel
```

## Current Boundaries

- No public REST API endpoints are implemented (despite DRF dependency in requirements).
- No built-in scheduler process is embedded; daily runs are designed for cron/Task Scheduler invoking `refresh_intel`.
- Operational hardening and deployment-specific infrastructure are intentionally minimal in this repository stage.
