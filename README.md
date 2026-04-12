# ThreatFoundry

ThreatFoundry is a Django 5 application for ingesting, normalizing, enriching, and triaging indicators of compromise (IOCs).

## Overview

The project currently provides:
- Multi-source IOC ingestion from ThreatFox, AlienVault OTX, and URLHaus
- Optional enrichment from VirusTotal
- Server-rendered analyst dashboard and IOC investigation views
- Analyst assistant UI with local database-backed responses and optional n8n webhook mode
- Provider and refresh run-history tracking for operations visibility

## Current Status

This repository is in active staging. Core ingestion, enrichment, dashboard, and refresh orchestration are implemented. Deployment automation (CI/CD, containerization, production infra) is not yet included.

## Tech Stack

- Python 3.11+
- Django 5.2
- SQLite by default, PostgreSQL optional
- Requests + service-layer provider integrations

## Quick Start

1. Install dependencies.

```bash
python -m pip install -r requirements.txt
```

2. Create your local env file.

```bash
# Linux/macOS
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

3. Update `.env` with your local values.

4. Run database migrations.

```bash
python manage.py migrate
```

5. Load IOC data.

```bash
# local demo data
python manage.py populate_sample_iocs
```

Or pull from providers:

```bash
python manage.py import_threatfox --days 1
python manage.py import_alienvault --days 1
python manage.py import_urlhaus
```

6. Start the app.

```bash
python manage.py runserver
```

Default bind: `0.0.0.0:8080`

7. Open:

```text
http://127.0.0.1:8080/
```

## Environment Variables

The app reads `.env` values using `python-dotenv` when available.

### Core Django

- `DJANGO_SECRET_KEY`: required when `DJANGO_DEBUG=false`
- `DJANGO_DEBUG`: `true` or `false`
- `DJANGO_ALLOWED_HOSTS`: comma-separated hosts
- `DJANGO_CSRF_TRUSTED_ORIGINS`: comma-separated origins
- `DJANGO_TIME_ZONE`: backend timezone (default `UTC`)
- `INTEL_LOCAL_TIME_ZONE`: analyst-facing display timezone (default `America/New_York`)

### Provider Credentials

- `THREATFOX_API_KEY` (fallback alias: `THREAT_FOX_API`)
- `OTX_API_KEY` (fallback alias: `OTX_API`)
- `VIRUSTOTAL_API_KEY` (fallback alias: `VT_API_KEY`)
- `URLHAUS_API_KEY` (optional)
- `ABUSEIPDB_API_KEY` (optional)
- `SHODAN_API_KEY` (optional)
- `NVD_API_KEY` (optional)

### Provider Toggles

Set provider switches with `<PROVIDER>_ENABLED=true|false`.
Examples: `THREATFOX_ENABLED`, `ALIENVAULT_ENABLED`, `URLHAUS_ENABLED`, `VIRUSTOTAL_ENABLED`.

### Refresh Pipeline

- `INTEL_REFRESH_SCHEDULE` (default `0 2 * * *`)
- `INTEL_REFRESH_DEFAULT_SINCE` (default `24h`)
- `INTEL_REFRESH_TIMEOUT` (seconds, default `30`)
- `INTEL_REFRESH_VIRUSTOTAL_LIMIT` (default `25`)
- `INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS` (default `16`)

### Analyst Assistant

- `INTEL_CHAT_PROVIDER`: `local`, `n8n`, or `hybrid`
- `INTEL_CHAT_MAX_CONTEXT_RECORDS`
- `INTEL_CHAT_N8N_WEBHOOK_URL`
- `INTEL_CHAT_N8N_TIMEOUT`
- `INTEL_CHAT_N8N_BEARER_TOKEN`

## Database Configuration

`config/settings.py` supports:
- SQLite (default): `db.sqlite3`
- PostgreSQL when `POSTGRES_DB` is set (with `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`)

## Migrations

Run all migrations:

```bash
python manage.py migrate
```

Inspect migration status:

```bash
python manage.py showmigrations
```

## Common Commands

### Ingestion and Enrichment

- `python manage.py import_threatfox --days 1`
- `python manage.py import_alienvault --days 1`
- `python manage.py import_urlhaus`
- `python manage.py import_virustotal --limit 25`

### Pipeline and Operations

- `python manage.py refresh_intel`
- `python manage.py refresh_intel --provider threatfox`
- `python manage.py refresh_intel --since 7d`
- `python manage.py refresh_intel --dry-run`
- `python manage.py cleanup_old_iocs`
- `python manage.py trim_ioc_samples --limit 500`

### Utility and Validation

- `python manage.py domain_search <query>`
- `python manage.py print_ioc_stats`
- `python manage.py print_latest_ioc`
- `python manage.py populate_sample_iocs`
- `python manage.py check`
- `python manage.py test intel`

## Web Routes

- `/` and `/dashboard/`: dashboard
- `/assistant/`: analyst assistant page
- `/api/assistant/chat/`: assistant API endpoint (POST)
- `/docs/`: in-app docs browser
- `/docs/<doc_name>/`: specific doc page
- `/malware/`: malware directory and family view
- `/ioc-blade/`: aggregated IOC blade detail
- `/ioc/<pk>/`: IOC detail
- `/admin/`: Django admin

## Documentation

Repository docs under `docs/` include architecture, feature behavior, operations runbook, and MCP server reference. They are also viewable in the app at `/docs/`.

## Optional n8n Integration

To route assistant requests to n8n, configure:

```env
INTEL_CHAT_PROVIDER=n8n
INTEL_CHAT_N8N_WEBHOOK_URL=https://<your-workspace>.app.n8n.cloud/webhook/soc-analyst-bot
INTEL_CHAT_N8N_TIMEOUT=20
INTEL_CHAT_N8N_BEARER_TOKEN=
```

Use `INTEL_CHAT_PROVIDER=hybrid` to fall back to local responses if n8n is unavailable.

## Security Notes

- Keep `.env` local and uncommitted.
- Keep `.env.example` placeholder-only.
- For non-local use, set `DJANGO_DEBUG=false` and provide a strong `DJANGO_SECRET_KEY`.

## Roadmap

- Deployment guide (service + reverse proxy + scheduler)
- CI checks (lint, tests, security scanning)
- Optional API surface expansion
- Optional containerization
