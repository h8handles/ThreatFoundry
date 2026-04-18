# Architecture Reference

## 1) High-Level Architecture

ThreatFoundry is a single Django project (`config`) with one domain app (`intel`) containing model, service, view, template, static, and command layers.

### Layered Breakdown

- Config and framework layer:
  - `config/settings.py`
  - `config/urls.py`
- Domain model layer:
  - `intel/models.py`
- Service layer:
  - `intel/services/*.py`
- Interface layer:
  - Web: `intel/views.py`, `intel/views_chat.py`, `intel/views_tickets.py`, templates, static assets
  - CLI: `intel/management/commands/*.py`

## 2) Data Model

## 2.1 `IntelIOC`

Purpose:

- Normalized IOC storage across providers, while preserving source payloads and enrichment payloads.

Notable fields:

- Identity and source:
  - `source_name`
  - `source_record_id`
- Indicator fields:
  - `value`
  - `value_type`
  - `threat_type`
  - `malware_family`
  - `confidence_level`
- Time and attribution:
  - `first_seen`
  - `last_seen`
  - `reporter`
- References and tagging:
  - `reference_url`
  - `tags` (JSON list)
  - `external_references` (JSON list)
- Payload retention:
  - `raw_payload` (JSON)
  - `enrichment_payloads` (JSON)
  - `last_enriched_at`
  - `last_enrichment_providers`
- Local lifecycle timestamps:
  - `created_at`
  - `updated_at`
  - `last_ingested_at`

Constraints and indexing:

- Unique constraint on `(source_name, source_record_id)`.
- Indexes on value, type, source, threat type, malware family.

## 2.2 `ProviderRun`

Purpose:

- Persist command-level provider run outcomes.

Used by import commands and enrichment command via `ProviderRunRecorder`.

## 2.3 `IngestionRun` and `ProviderRunDetail`

Purpose:

- Persist orchestrated refresh runs (`refresh_intel`) with top-level and per-provider execution details.

Relationship:

- `ProviderRunDetail.ingestion_run -> IngestionRun` (foreign key).

## 2.4 `Ticket`

Purpose:

- Persist analyst-created investigation tickets.

Notable fields:

- `title`
- `description`
- `status`
- `priority`
- `created_by`
- `assigned_to`
- `created_at`
- `updated_at`

Ordering and indexes favor queue-style views by status, priority, assignee, and recent updates.

## 2.5 `TicketNote`

Purpose:

- Persist chronological analyst notes attached to tickets.

Relationship:

- `TicketNote.ticket -> Ticket`
- `TicketNote.author -> AUTH_USER_MODEL`

Notes are ordered by creation time and ID so the activity feed remains stable.

## 3) Service Boundaries

## 3.1 Ingestion Service (`intel/services/ingestion.py`)

Responsibilities:

- Normalize provider-specific records into shared IOC shape.
- Parse source datetime formats and clean tags.
- Upsert records with dedupe semantics.

Supported normalizers:

- ThreatFox
- AlienVault OTX
- URLHaus

## 3.2 Provider Fetch Services

- `threatfox.py`: ThreatFox API call.
- `alienvault.py`: OTX export API call.
- `urlhaus.py`: URLHaus recent URLs API call.
- `virustotal.py`: VirusTotal lookups and enrichment shaping.

These modules focus on provider protocol and payload handling, while the ingestion service handles normalized persistence.

## 3.3 Provider Registry (`intel/services/provider_registry.py`)

Responsibilities:

- Provider metadata catalog.
- Enable/disable state resolution from env vars and key presence.
- Missing-key reporting for UI availability panels.
- Provider-specific external-link builders.

## 3.4 Dashboard Aggregation (`intel/services/dashboard.py`)

Responsibilities:

- Parse dashboard filters from query parameters.
- Build filtered queryset and sort state.
- Compute KPIs and chart datasets.
- Build table rows with source/context links.
- Build malware directory/family contexts.
- Build IOC blade list/detail contexts.
- Build per-record detail sections and VirusTotal detail context.

## 3.5 Correlation (`intel/services/correlation.py`)

Responsibilities:

- Detect hash IOC applicability.
- Perform exact ThreatFox hash correlation.
- Return analyst-friendly family/threat summaries and match rows.

## 3.6 Refresh Pipeline (`intel/services/refresh_pipeline.py`)

Responsibilities:

- Parse refresh window (`--since`).
- Discover applicable providers.
- Execute ingestion/enrichment providers.
- Handle skip/failure/partial semantics.
- Persist `IngestionRun` and `ProviderRunDetail` records.
- Optionally refresh dashboard snapshot metadata.

## 4) Web Request Flow

### 4.1 Dashboard Request

1. `dashboard_view` parses request filters.
2. `build_dashboard_context` composes aggregations and rows.
3. `dashboard.html` renders filters, KPIs, charts, table.
4. `dashboard.js` initializes Chart.js visualizations.

### 4.2 IOC Detail Request

1. `ioc_detail_view` loads `IntelIOC` by PK.
2. `build_detail_context` adds normalized/source context.
3. `build_hash_correlation_context` adds ThreatFox correlation data.
4. `json.dumps(record.raw_payload, indent=2, sort_keys=True)` prepares payload view.
5. `ioc_detail.html` renders sections conditionally.

### 4.3 Documentation Request

1. `documentation_view` enumerates markdown files in `docs/`.
2. Selected markdown file is converted with `markdown` library.
3. Full page or partial content is rendered depending on AJAX header.
4. Frontend JS updates page content and browser history.

### 4.4 Ticket Workspace Request

1. `ticket_list_view` enforces analyst access and loads the ticket queue.
2. POSTs to `/tickets/` create a ticket through `TicketCreateForm`.
3. `ticket_detail_view` loads a ticket and processes update submissions through `TicketUpdateForm`.
4. `ticket_note_create_view` accepts POST-only note submissions through `TicketNoteForm`.
5. `ticket_detail.html` renders the ticket record workspace, while `tickets.js` handles UI-only behavior such as tabs, collapsible panels, auto-growing textareas, and safe popout opening.

Ticket routes reuse the authenticated Django session and do not move note content, tokens, prompts, or privileged state into URLs or browser storage.

## 5) CLI Command Architecture

Each management command is a thin orchestration layer that delegates business logic to services.

Patterns used:

- Fetch provider payload.
- Extract payload records when needed.
- Normalize and upsert via ingestion service.
- Track execution metrics and status.
- Return human-readable CLI status output.

`refresh_intel` centralizes multi-provider orchestration and run-detail persistence.

## 6) Time and Rendering Architecture

### 6.1 Time Preference Stack

- Session key stores selected display option.
- Context processor injects options and current selection globally.
- Template tag `display_datetime` performs rendering based on selected mode.

### 6.2 Timezone Rules

- UTC mode uses UTC conversion and explicit suffix.
- Local modes convert to `INTEL_LOCAL_TIME_ZONE` (zoneinfo-backed with fallback).

## 7) Configuration Architecture

Key settings areas in `config/settings.py`:

- Django base settings.
- Template setup and context processors.
- SQLite default + PostgreSQL switch.
- intel refresh controls (timeout, since, schedule, VT limits/throttle).

Environment loading:

- `.env` loaded via `python-dotenv` if available.
- fallback inline parser if `python-dotenv` is absent.

## 8) Integration and Extensibility Notes

### 8.1 Adding an Ingestion Provider

1. Add provider metadata in registry.
2. Add fetch module under `intel/services/`.
3. Add normalizer in `ingestion.py`.
4. Add import command (optional standalone command).
5. Wire provider into refresh pipeline.
6. Add tests and docs updates.

### 8.2 Adding an Enrichment Provider

1. Add provider metadata and enablement rules in registry.
2. Implement enrichment fetch/transform service.
3. Merge enrichment into `IntelIOC.enrichment_payloads`.
4. Add platform field-derivation rules (if needed).
5. Add detail rendering support.
6. Add tests and docs updates.

## 9) Current Architectural Tradeoffs

- Single app (`intel`) keeps iteration speed high but concentrates many responsibilities.
- `dashboard.py` carries significant aggregation/presentation logic in one module.
- Server-rendered UI keeps deployment simple and reduces API overhead.
- Scheduling is externalized, keeping app runtime simpler at current project stage.
- Ticket workspace tabs are intentionally client-side UI state. The source of truth for tickets and notes remains the database.
