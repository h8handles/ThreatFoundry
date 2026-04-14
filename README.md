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

5. Create your first login.

```bash
python manage.py createsuperuser
```

Superusers can use Django admin immediately. Baseline access groups are also created by migration:
- `admin`
- `analyst`
- `viewer`

Assign non-superuser accounts to one of those groups in `/admin/` before using the app.
Users can also self-register at `/auth/register/`; self-registered accounts are assigned `viewer` by default.

6. Load IOC data.

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

7. Start the app.

```bash
python manage.py runserver
```

Default bind: `localhost:8080`

8. Open:

```text
http://localhost:8080/
```

## Environment Variables

The app reads `.env` values using `python-dotenv` when available.

### Core Django

- `DJANGO_SECRET_KEY`: required when `DJANGO_DEBUG=false`
- `DJANGO_DEBUG`: `true` or `false`
- `DJANGO_RUNSERVER_HOST`: default dev bind address (default `172.30.150.130`)
- `DJANGO_RUNSERVER_PORT`: default dev bind port (default `8080`)
- `DJANGO_ALLOWED_HOSTS`: comma-separated hosts; leave blank in local debug mode to allow dev hosts/tunnels
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
WIP linux feature
- `INTEL_REFRESH_SCHEDULE` (default `0 2 * * *`)
- `INTEL_REFRESH_DEFAULT_SINCE` (default `24h`)
- `INTEL_REFRESH_TIMEOUT` (seconds, default `30`)
- `INTEL_REFRESH_LOG_FILE` (default `BASE_DIR/var/log/refresh_intel.log`)
- `INTEL_REFRESH_LOCK_FILE` (default `BASE_DIR/var/run/refresh_intel.lock`)
- `INTEL_REFRESH_VIRUSTOTAL_LIMIT` (default `25`)
- `INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS` (default `16`)

### Analyst Assistant

- `INTEL_CHAT_PROVIDER`: `local`, `n8n`, or `hybrid`
- `INTEL_CHAT_MAX_CONTEXT_RECORDS`
- `INTEL_CHAT_N8N_WEBHOOK_URL`
- `INTEL_CHAT_N8N_TIMEOUT`
- `INTEL_CHAT_N8N_BEARER_TOKEN`
- `INTEL_CHAT_CONTEXT_API_TOKEN`

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
- `python manage.py refresh_intel_scheduled`
- `python manage.py refresh_intel --provider threatfox`
- `python manage.py refresh_intel --since 7d`
- `python manage.py refresh_intel --dry-run`
- `python manage.py correlate_unknowns`
- `python manage.py correlate_unknowns --limit 100`
- `python manage.py cleanup_old_iocs`
- `python manage.py trim_ioc_samples --limit 500`

## Automated Refresh In WSL2

Use external scheduling. The repository now includes `python manage.py refresh_intel_scheduled`, which wraps the existing `refresh_intel` flow, writes a logfile, and skips overlapping runs by taking a lockfile.

Recommended WSL2 setup:

1. Set optional paths in `.env` if you do not want the defaults:
   `INTEL_REFRESH_LOG_FILE=/home/<user>/ThreatFoundry/var/log/refresh_intel.log`
   `INTEL_REFRESH_LOCK_FILE=/home/<user>/ThreatFoundry/var/run/refresh_intel.lock`
2. Verify the scheduled entrypoint manually:
   `python manage.py refresh_intel_scheduled --no-feed-refresh`
3. Start cron in WSL2.
   If your distro is using systemd, `sudo systemctl enable --now cron`
   Otherwise, `sudo service cron start`
4. Install the cron entry with `crontab -e`:

```cron
0 2 * * * cd /home/<user>/ThreatFoundry && /home/<user>/ThreatFoundry/threatfoundry/bin/python manage.py refresh_intel_scheduled --timeout 30
```

The command itself appends to the configured logfile, records per-provider outcomes in the database, preserves provider enable/disable rules, and continues past individual provider failures.

### Utility and Validation

- `python manage.py domain_search <query>`
- `python manage.py print_ioc_stats`
- `python manage.py print_latest_ioc`
- `python manage.py populate_sample_iocs`
- `python manage.py check`
- `python manage.py test intel`

## Web Routes

- `/auth/login/`: login page
- `/auth/register/`: self-service local registration page, defaults new users to `viewer`
- `/auth/logout/`: logout endpoint
- `/` and `/dashboard/`: dashboard, requires `viewer` or higher
- `/assistant/`: analyst assistant page, requires `analyst` or higher
- `/api/assistant/chat/`: assistant API endpoint (POST), requires authenticated `analyst` or higher
- `/api/assistant/context/`: assistant context API endpoint (POST), requires analyst auth or a valid `X-ThreatFoundry-Service-Token`
- `/docs/`: in-app docs browser, requires `viewer` or higher
- `/docs/<doc_name>/`: specific doc page, requires `viewer` or higher
- `/malware/`: malware directory and family view, requires `viewer` or higher
- `/ioc-blade/`: aggregated IOC blade detail, requires `viewer` or higher
- `/ioc/<pk>/`: IOC detail, requires `viewer` or higher
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
INTEL_CHAT_CONTEXT_API_TOKEN=
```

Use `INTEL_CHAT_PROVIDER=hybrid` to fall back to local responses if n8n is unavailable.

## Security Notes

- Keep `.env` local and uncommitted.
- Keep `.env.example` placeholder-only.
- For non-local use, set `DJANGO_DEBUG=false` and provide a strong `DJANGO_SECRET_KEY`.
- ThreatFoundry now defaults to authenticated access for analyst-facing routes.
- Role baseline:
  - `viewer`: read-only access to dashboard, docs, malware, and IOC investigation pages
  - `analyst`: viewer access plus analyst assistant UI/API
  - `admin`: administrator access and compatibility with analyst/viewer checks

## Correlation Engine

- `python manage.py correlate_unknowns` correlates partially unknown IOCs against locally stored IOC and enrichment evidence.
- The engine never overwrites source-native `threat_type`, `malware_family`, or `confidence_level`.
- Derived outputs are stored separately on each IOC:
  - `derived_confidence_level`
  - `likely_threat_type`
  - `likely_malware_family`
  - `correlation_reasons`
- Promotions only happen when the derived score is `>= 60`; lower-confidence results retain unknown classifications and store reasons only.

## Roadmap

- Deployment guide (service + reverse proxy + scheduler)
- CI checks (lint, tests, security scanning)
- Optional API surface expansion
- Optional containerization
