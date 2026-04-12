# Feature Reference

This document inventories implemented features in the current repository.

## 1) Web Interface Features

### 1.1 Global Navigation and Layout

- Top navigation links:
  - Dashboard
  - Malware Workspaces
  - Documentation
  - Admin
- Global time-format selector in topbar.
- Shared static assets:
  - `intel/static/intel/dashboard.css`
  - `intel/static/intel/dashboard.js`
  - `intel/static/intel/threatfoundry-mark.svg`
- Chart rendering via Chart.js CDN.

### 1.2 Dashboard (`/`, `/dashboard/`)

#### Filters

- IOC value search text (`search`).
- Tag search text (`tag`).
- Start/end date filters (`start_date`, `end_date`).
- IOC type filter (`value_type`).
- Malware family filter (`malware_family`).
- Threat type filter (`threat_type`).
- Confidence-band filter (`confidence_band`).

#### Filter UX

- Active-filter chip display.
- Clear-all shortcut.
- Filtered-result count.

#### Sorting and Pagination

- Sort fields:
  - value
  - type
  - source
  - confidence
  - threat
  - observed
  - ingested
- Asc/desc direction toggling per header.
- Page navigation.
- Page-size options: 10, 25, 50, 100.

#### KPI Cards

- Total IOCs.
- Malware-family count.
- IOC-type count.
- Unique-tag count.
- Average confidence.
- Newest ingest.
- Oldest timeline timestamp in scope.

#### Charts

- IOC volume over time (line chart).
- IOC type distribution (doughnut).
- Confidence distribution (bar).
- Malware family distribution (horizontal bar).

#### Context Panels

- Top tags list.
- Threat-type snapshot list.
- Provider readiness panel (enabled vs not available).

#### Search Aggregation Feature

When `search` is present:

- Aggregated IOC blade cards appear.
- One blade represents a unique `(value_type, value)` group.
- Blade summarizes:
  - combined source coverage
  - total matching records
  - references count
  - threat summary
  - malware summary
  - latest observed/ingested timestamps

#### Data Table: Latest IOCs

Per-row display includes:

- IOC value.
- IOC type label.
- summary title/meta.
- observed timestamp.
- ingested timestamp.
- source badges.
- provider links/references.
- optional tags and malware-family link.

### 1.3 IOC Detail (`/ioc/<pk>/`)

#### Overview Section

- Normalized IOC metadata cards from `build_detail_context`.

#### Source-Specific Context

- Dynamic detail sections based on source and available fields.

#### Hash Correlation

- Exact-match ThreatFox correlation for hash IOC types.
- Supported hash aliases:
  - `FileHash-MD5` / `md5_hash`
  - `FileHash-SHA1` / `sha1_hash`
  - `FileHash-SHA256` / `sha256_hash`
- Displays:
  - applicability message
  - inferred malware families with counts
  - related threat types with counts
  - exact ThreatFox match table

#### VirusTotal Enrichment Rendering

If enrichment exists:

- Analysis summary section.
- Classification signals section.
- Artifact details section (type-aware fields).
- Raw VirusTotal enrichment payload.
- Reference link and optional note.

#### External References

- Grouped by provider (native source and enrichment providers).
- Supports link notes where present.

#### Raw Source Payload Viewer

- Pretty-printed JSON payload.
- Scroll-bounded container for large payloads.

### 1.4 IOC Blade Detail (`/ioc-blade/`)

Inputs:

- `value`
- `value_type`

Features:

- Aggregated summary across all matching records/providers.
- Source-level breakdown section with:
  - record IDs
  - threat types
  - malware families
  - confidence values
  - reporters
  - last seen
  - tags
  - external links
- Side panel showing source coverage chips.

### 1.5 Malware Workspace

#### Directory (`/malware/` with no `family`)

- Family cards with IOC counts, source counts, newest-seen timestamp.

#### Family Drill-down (`/malware/?family=<name>`)

- Family KPI summary.
- Charts:
  - observed activity timeline
  - indicator mix
  - source split
- Family traits list.
- Related IOC table with pagination/page size.
- Family references panel.
- Family top tags and threat snapshot panels.

### 1.6 Documentation Wiki (`/docs/`, `/docs/<doc_name>/`)

- Auto-discovers markdown files in `docs/`.
- Sidebar page navigation.
- AJAX content swap for smooth page navigation.
- Browser history integration (`pushState`, `popstate`).
- Markdown rendering with table and fenced-code support.

### 1.7 Time Display Preferences

- Session key: `intel_time_display_option`.
- Supported options:
  - Friendly local (12-hour)
  - Local (24-hour)
  - UTC (24-hour)
- Per-request rendering via `display_datetime` template tag.
- Local timezone defaults to `INTEL_LOCAL_TIME_ZONE` (fallback `America/New_York`).

## 2) Ingestion and Enrichment Features

### 2.1 Ingestion Normalization

Shared normalized IOC shape includes:

- source identity
- value and type
- threat/malware fields
- confidence
- first/last seen
- reporter
- reference URL
- tags
- external references
- raw payload

### 2.2 Upsert and Deduplication

- Dedupe key: `(source_name, source_record_id)`.
- Operation: `update_or_create` on each normalized record.
- Supports dry-run mode in refresh orchestration.

### 2.3 ThreatFox Integration

- API endpoint: `https://threatfox-api.abuse.ch/api/v1/`.
- API key support:
  - `THREATFOX_API_KEY`
  - fallback `THREAT_FOX_API`
- Ingestion command includes `--days` window.

### 2.4 AlienVault OTX Integration

- API endpoint: `https://otx.alienvault.com/api/v1/indicators/export`.
- API key support:
  - `OTX_API_KEY`
  - fallback `OTX_API`
- Extracts records from multiple payload shapes (`results`, `data`, `indicators`).
- Normalizer maps pulse/context fields and reference/tag data.

### 2.5 URLHaus Integration

- API endpoint: `https://urlhaus-api.abuse.ch/v1/urls/recent/`.
- Works without auth key; optional `URLHAUS_API_KEY` header support.
- Ingestion command supports request timeout control.

### 2.6 VirusTotal Enrichment

- API base: `https://www.virustotal.com/api/v3`.
- API key support:
  - `VIRUSTOTAL_API_KEY`
  - fallback `VT_API_KEY`
- IOC lookup support:
  - file hashes
  - domains/hostnames
  - IPs
  - IP:port (IP extracted)
  - URLs (base64 URL identifier path)
- Enrichment payload persisted under `enrichment_payloads["virustotal"]`.
- Derives platform updates:
  - malware family
  - threat type
  - confidence level
  - reference URL
  - tags
- Adds provider GUI links into `external_references`.
- Optional throttling between requests.
- Handles unsupported lookups and not-found cases explicitly.

### 2.7 Provider Capability and Link Registry

Centralized provider metadata includes:

- category (`ingestion`, `enrichment`, `vulnerability_intel`, `ttp_intel`)
- required/optional env vars
- enable-state logic (`<PROVIDER>_ENABLED`)
- note text
- provider-specific external-link builders

Implemented link-build patterns include:

- ThreatFox record links
- AlienVault indicator links
- URLHaus URL/host links
- VirusTotal GUI links (file/domain/ip/url)
- AbuseIPDB link format for IPs
- Shodan host links for IPs

## 3) Refresh Orchestration and Run Tracking

### 3.1 `refresh_intel` Pipeline

- Discovers providers from registry.
- Executes implemented providers.
- Skips disabled or not-implemented providers with explicit reason.
- Supports provider targeting and time-window parsing.
- Optionally refreshes dashboard snapshot metadata.

### 3.2 Time Window Parsing

Supported `--since` styles:

- Relative windows like `24h`, `7d`, `15m`, `2w`.
- ISO datetime string.

### 3.3 Persistence of Run History

- Top-level run record: `IngestionRun`.
- Per-provider records: `ProviderRunDetail`.
- Per-command provider runs: `ProviderRun`.

Tracked metrics include:

- fetched/created/updated/skipped counts
- success/failure/partial/skipped status
- error summary and details
- started/finished timestamps
- dry-run and refresh options

## 4) CLI Command Features

### 4.1 Import and Refresh Commands

- `import_threatfox --days N`
- `import_alienvault --days N`
- `import_urlhaus --timeout N`
- `import_virustotal` with limit/source/type/force/timeout/throttle options
- `refresh_intel` with provider/since/timeout/dry-run/feed-refresh controls

### 4.2 Utility Commands

- `domain_search <query> [--limit N] [--exact]`
- `print_ioc_stats`
- `print_latest_ioc`
- `populate_sample_iocs [--reset-samples]`

### 4.3 Development Server Convenience

- `python manage.py runserver` defaults to `0.0.0.0:8080`.

## 5) Testing Coverage Areas

`intel/tests.py` includes tests for:

- normalization behavior (AlienVault, URLHaus)
- provider-link generation
- provider availability states
- provider run recorder behavior
- refresh pipeline outcomes (success/partial/dry-run)
- dashboard sorting/pagination/rendering expectations
- IOC detail and blade detail rendering
- VirusTotal enrichment merge behavior
- sample-data command behavior
- time-display preference behavior

## 6) Not-Implemented/Out-of-Scope in This Repo

- No public REST API endpoints are implemented.
- No built-in scheduler daemon; scheduling is external (cron/Task Scheduler).
- Some registry providers are placeholders/structure-only and do not yet run in refresh ingestion.
