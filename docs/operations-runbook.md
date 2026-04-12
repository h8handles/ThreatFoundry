# Operations Runbook

## 1) Environment Setup

## 1.1 Install and Bootstrap

```bash
python -m pip install -r requirements.txt
copy .env.example .env
python manage.py migrate
```

## 1.2 Optional Seed Data

```bash
python manage.py populate_sample_iocs
```

This creates representative IOC records across provider/source shapes, including large payloads for detail-view validation.

## 1.3 Start Local App

```bash
python manage.py runserver
```

Default bind from custom command:

- Address: `0.0.0.0`
- Port: `8080`

Open:

- `http://127.0.0.1:8080/`

## 2) Core Environment Variables

### 2.1 Django

- `DJANGO_SECRET_KEY`
- `DJANGO_DEBUG`
- `DJANGO_ALLOWED_HOSTS`
- `DJANGO_CSRF_TRUSTED_ORIGINS`
- `DJANGO_TIME_ZONE`
- `INTEL_LOCAL_TIME_ZONE`

### 2.2 Provider Keys

- `THREATFOX_API_KEY`
- `OTX_API_KEY`
- `URLHAUS_API_KEY` (optional)
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY` (optional; readiness/link support)
- `SHODAN_API_KEY` (optional; readiness/link support)
- `NVD_API_KEY` (optional)

Compatibility fallbacks:

- ThreatFox: `THREAT_FOX_API`
- AlienVault: `OTX_API`
- VirusTotal: `VT_API_KEY`

### 2.3 Provider Toggles

- `<PROVIDER>_ENABLED=true|false`
- Examples:
  - `THREATFOX_ENABLED=true`
  - `VIRUSTOTAL_ENABLED=false`

### 2.4 Refresh Pipeline Controls

- `INTEL_REFRESH_SCHEDULE`
- `INTEL_REFRESH_DEFAULT_SINCE`
- `INTEL_REFRESH_TIMEOUT`
- `INTEL_REFRESH_VIRUSTOTAL_LIMIT`
- `INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS`

### 2.5 Database

Default:

- SQLite (`db.sqlite3`)

PostgreSQL mode triggers when `POSTGRES_DB` is set; companion vars:

- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_HOST`
- `POSTGRES_PORT`

## 3) Daily/On-Demand Ingestion Commands

## 3.1 Provider-Specific Imports

### ThreatFox

```bash
python manage.py import_threatfox --days 1
```

### AlienVault OTX

```bash
python manage.py import_alienvault --days 1
```

### URLHaus

```bash
python manage.py import_urlhaus --timeout 30
```

## 3.2 VirusTotal Enrichment

Basic run:

```bash
python manage.py import_virustotal --limit 25
```

Common options:

```bash
python manage.py import_virustotal --limit 50 --source threatfox --source alienvault
python manage.py import_virustotal --value-type domain --value-type FileHash-MD5
python manage.py import_virustotal --force
python manage.py import_virustotal --timeout 45 --throttle-seconds 16
```

Behavior notes:

- By default enriches records not already enriched by VirusTotal.
- `--force` re-enriches already-enriched records.
- Unsupported IOC types and not-found reports are tracked as skipped categories.

## 3.3 Orchestrated Refresh (`refresh_intel`)

Default:

```bash
python manage.py refresh_intel
```

Common variants:

```bash
python manage.py refresh_intel --provider threatfox
python manage.py refresh_intel --since 24h
python manage.py refresh_intel --since 7d
python manage.py refresh_intel --since 2026-04-11T00:00:00Z
python manage.py refresh_intel --timeout 45
python manage.py refresh_intel --dry-run
python manage.py refresh_intel --no-feed-refresh
```

Behavior notes:

- Runs enabled and implemented providers.
- Disabled/unconfigured providers are skipped with explicit reason.
- Not-yet-implemented providers in registry are skipped cleanly.
- Partial success is possible when one or more providers fail while others succeed.

## 4) Verification and Health Checks

## 4.1 Command-Level Checks

```bash
python manage.py check
python manage.py print_ioc_stats
python manage.py print_latest_ioc
python manage.py domain_search example.com
python manage.py domain_search example.com --exact --limit 5
```

## 4.2 Test Suite

```bash
python manage.py test intel
```

## 4.3 What to Inspect in Admin

Use `/admin/` to inspect:

- `IntelIOC`
- `ProviderRun`
- `IngestionRun`
- `ProviderRunDetail`

Recommended quick checks:

- Latest run statuses and timestamps.
- Failure/skip error summaries.
- Counts (fetched/created/updated/skipped).
- Presence of `enrichment_payloads.virustotal` after enrichment commands.

## 5) Scheduling Guidance

No in-process scheduler is bundled; schedule external invocation of `refresh_intel`.

## 5.1 Cron (Linux/macOS)

Example for default 02:00 schedule:

```cron
0 2 * * * cd /path/to/ioc_project && /path/to/python manage.py refresh_intel >> /var/log/ioc_refresh.log 2>&1
```

## 5.2 Windows Task Scheduler

- Program/script: path to `python.exe`
- Arguments: `manage.py refresh_intel`
- Start in: repository root path

## 6) Troubleshooting

## 6.1 Provider Marked Not Available

Symptoms:

- Dashboard provider readiness shows "Not available".
- Import/refresh command reports provider skipped.

Checks:

- Confirm required API key env var exists and is non-empty.
- Confirm `<PROVIDER>_ENABLED` is not false.
- Re-run command from same shell/session where env vars are loaded.

## 6.2 `refresh_intel` Ends Partial or Failure

Checks:

- Inspect command output for per-provider status lines.
- Review `IngestionRun` and related `ProviderRunDetail` rows in admin.
- Confirm network connectivity and provider API availability.
- Retry with a single provider using `--provider` to isolate failure.

## 6.3 VirusTotal Runs Slowly

Expected cause:

- Throttling is intentional to respect quota.

Adjustments:

- Reduce `--limit`.
- Use narrower filters (`--source`, `--value-type`).
- Tune `--throttle-seconds` carefully.

## 6.4 No Records on Dashboard

Checks:

- Run `python manage.py print_ioc_stats`.
- Import data (`import_threatfox`, `import_alienvault`, `import_urlhaus`) or seed sample data.
- Clear filters in dashboard UI.

## 6.5 Documentation Page Missing

Checks:

- Ensure markdown file exists in `docs/`.
- Ensure file extension is `.md`.
- Reload `/docs/` and select page from sidebar.

## 7) Change Management Checklist

When changing provider behavior or UI filtering/sorting logic:

1. Update relevant `docs/*.md` pages.
2. Run tests (`python manage.py test intel`).
3. Validate dashboard route and detail route manually.
4. Validate command output and run-tracking records.
5. Confirm `.env.example` still reflects required config.
