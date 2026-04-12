# MCP Server Reference

This project includes a local Model Context Protocol (MCP) server at `mcp_server/`.

## Purpose

The server exposes a safe, bounded interface for:

- IOC and ingestion data lookups from the Django models.
- Project context resources (schema summaries, provider status, file map).
- Controlled engineering helpers (code search, bounded file reads, bounded `manage.py` and `pytest` execution).
- Reusable investigation/debugging prompts.

Transport is `stdio` only and the server is implemented directly in Python JSON-RPC.

## Run

From the repository root:

```bash
python -m mcp_server
```

Startup confirmation is written to `stderr`:

- `[ioc-project-mcp] starting version=... transport=stdio`
- `[ioc-project-mcp] stopped`

Runtime behavior:

- Entry point: `mcp_server/__main__.py`
- Server loop + JSON-RPC dispatch: `mcp_server/server.py`
- Django bootstrapping: `mcp_server/context.py`

The server sets `DJANGO_SETTINGS_MODULE=config.settings` if it is not already present, then runs `django.setup()` on first resource/tool call.

## MCP Capabilities

Initialization response (`initialize`) advertises:

- Protocol version: `2024-11-05`
- Server name: `ioc-project-mcp`
- Server version: `0.1.0`
- Capabilities: `resources`, `tools`, `prompts`

Supported protocol methods:

- `initialize`
- `ping`
- `shutdown`
- `notifications/initialized`
- `resources/list`
- `resources/read`
- `tools/list`
- `tools/call`
- `prompts/list`
- `prompts/get`

## Resources

Resource handlers are in `mcp_server/resources.py`.

### `ioc://project/overview`

High-level project metadata:

- Project root and Django settings module.
- Database engine.
- IOC counts by source.
- Available local management commands.
- Installed Django apps.

### `ioc://project/db-schema-summary`

Compact schema summary for `IntelIOC`, `ProviderRun`, and `IngestionRun`:

- Fields, nullability, PK flags, indexed fields, unique constraints.

### `ioc://project/provider-status-summary`

Provider availability and latest provider run summary using the provider registry.

### `ioc://project/file-map`

Directory/file summary for `config`, `intel`, `docs`, `testing`, `mcp_server`:

- Total files.
- Python file count.
- Sample Python paths.

### `ioc://project/recent-errors-summary`

Recent failures/partial outcomes from:

- `ProviderRun` (`failure`, `partial`).
- `IngestionRun` with non-empty `error_summary`.

### `ioc://project/recent-ingestion-run-summary`

Recent ingestion run snapshot with status, provider counts, and record counters.

## Tools

Tool metadata and handlers are in `mcp_server/tools.py`.

All tool calls return MCP content plus `structuredContent` and `isError`.

### Data/Operational Tools

- `lookup_ioc`
  - Inputs: `query` (required), `match_mode` (`contains|exact`), `limit` (`1-100`)
  - Behavior: Search IOC rows by value/source record/malware family/threat type (+tags in contains mode).

- `source_health`
  - Inputs: optional `provider`
  - Behavior: Provider availability + latest run details.

- `provider_registry_inspection`
  - Inputs: optional `provider`
  - Behavior: Same provider registry inspection output as `source_health`.

- `recent_ingestion_run_summary`
  - Inputs: `limit` (`1-50`)
  - Behavior: Compact ingestion run summaries.

- `compact_db_schema_introspection`
  - Inputs: none
  - Behavior: Compact model/table schema metadata.

### Repository/Code Tools

- `search_code`
  - Inputs: `query` (required), `path`, `glob`, `limit` (`1-200`)
  - Behavior: Uses `rg` with safe bounds; falls back to Python regex file scan if `rg` is unavailable.

- `read_file`
  - Inputs: `path` (required), `start_line`, `end_line`
  - Behavior: Reads a bounded line range from UTF-8 files under project root only.

### Bounded Execution Tools

- `run_manage_py`
  - Inputs: `command` (required), `args[]`, `read_only`, `timeout_seconds`
  - Restrictions:
    - `read_only=false` is rejected.
    - Command must be in allowlist.
    - Commands in explicit denylist are blocked (`shell`, `dbshell`, `runserver`, `createsuperuser`, etc.).
    - Arguments are restricted to a safe-character regex.

- `run_tests`
  - Inputs: optional `target`, `keyword`, `max_failures`, `timeout_seconds`
  - Behavior: Runs bounded `pytest -q --maxfail=N` with optional target and `-k`.

- `explain_traceback`
  - Inputs: `traceback` text (required)
  - Behavior: Parses frames/exceptions and returns likely root-cause categories.

## Prompts

Prompt templates are in `mcp_server/prompts.py`.

- `investigate_ioc`
- `fix_ingestion_bug`
- `improve_dashboard`
- `improve_chatbot`

Each prompt returns a compact, structured step plan as MCP prompt content.

## Security And Guardrails

Key safety boundaries:

- Path access is restricted to repository root via `safe_path`.
- No arbitrary shell tool is exposed.
- `run_manage_py` is read-only and allowlist-based.
- Tool output is size-bounded (`truncate_text`) to avoid unbounded payloads.
- JSON output is compact and ASCII-safe for predictable transport.

## Extending The Server

To add new MCP surface area:

1. Add metadata + handler in `resources.py`, `tools.py`, or `prompts.py`.
2. Register dispatch route in `server.py` only if adding a new protocol method category.
3. Keep any subprocess execution bounded by timeouts and argument/path validation.
4. Prefer returning stable schemas (`schema`, `schema_version`) for new structured outputs.
