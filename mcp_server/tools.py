from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

from mcp_server.context import CTX
from mcp_server.utils import (
    normalize_limit,
    rel_path,
    to_compact_json,
    truncate_text,
    validate_safe_args,
)


DISALLOWED_MANAGE_COMMANDS = {
    "shell",
    "dbshell",
    "runserver",
    "createsuperuser",
    "changepassword",
    "startapp",
    "startproject",
    "compilemessages",
    "makemessages",
}

READ_ONLY_MANAGE_COMMANDS = {
    "check",
    "showmigrations",
    "print_ioc_stats",
    "print_latest_ioc",
    "domain_search",
}
TRACEBACK_EXC_RE = re.compile(r"^([A-Za-z_][\w\.]*):\s*(.*)$")
FRAME_RE = re.compile(r'^\s*File "([^"]+)", line (\d+), in (.+)$')


TOOL_ITEMS = [
    {
        "name": "lookup_ioc",
        "description": "Find IOC rows by exact or partial match.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "match_mode": {"type": "string", "enum": ["contains", "exact"], "default": "contains"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "source_health",
        "description": "Summarize provider enablement and latest run health.",
        "inputSchema": {
            "type": "object",
            "properties": {"provider": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "provider_registry_inspection",
        "description": "Inspect provider registry availability and latest run details.",
        "inputSchema": {
            "type": "object",
            "properties": {"provider": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "recent_ingestion_run_summary",
        "description": "Return a compact summary of recent ingestion runs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "compact_db_schema_introspection",
        "description": "Return compact database schema introspection.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "search_code",
        "description": "Search code by regex pattern using ripgrep with safe bounds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "path": {"type": "string", "description": "Relative path under project root."},
                "glob": {"type": "string", "default": "*"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 30},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_file",
        "description": "Read a bounded file range from the repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1, "default": 1},
                "end_line": {"type": "integer", "minimum": 1},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_manage_py",
        "description": "Run allowlisted Django management commands safely.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "args": {"type": "array", "items": {"type": "string"}},
                "read_only": {"type": "boolean", "default": True},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300, "default": 60},
            },
            "required": ["command"],
            "additionalProperties": False,
        },
    },
    {
        "name": "run_tests",
        "description": "Run bounded pytest execution.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "keyword": {"type": "string"},
                "max_failures": {"type": "integer", "minimum": 1, "maximum": 20, "default": 1},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "default": 180},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "explain_traceback",
        "description": "Parse traceback text and summarize likely root cause.",
        "inputSchema": {
            "type": "object",
            "properties": {"traceback": {"type": "string"}},
            "required": ["traceback"],
            "additionalProperties": False,
        },
    },
]


def list_tools() -> dict:
    return {"tools": TOOL_ITEMS}


def call_tool(name: str, arguments: dict | None) -> dict:
    payload = arguments or {}
    handlers = {
        "lookup_ioc": tool_lookup_ioc,
        "source_health": tool_source_health,
        "provider_registry_inspection": tool_provider_registry_inspection,
        "recent_ingestion_run_summary": tool_recent_ingestion_run_summary,
        "compact_db_schema_introspection": tool_compact_db_schema_introspection,
        "search_code": tool_search_code,
        "read_file": tool_read_file,
        "run_manage_py": tool_run_manage_py,
        "run_tests": tool_run_tests,
        "explain_traceback": tool_explain_traceback,
    }
    handler = handlers.get(name)
    if handler is None:
        raise ValueError(f"unknown tool: {name}")
    result = handler(payload)
    return {
        "content": [{"type": "text", "text": to_compact_json(result)}],
        "structuredContent": result,
        "isError": not bool(result.get("ok", False)),
    }


def tool_lookup_ioc(args: dict) -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    query = str(args.get("query", "")).strip()
    if not query:
        return CTX.as_json_error("bad_request", "query is required")
    match_mode = str(args.get("match_mode", "contains")).strip().lower()
    if match_mode not in {"contains", "exact"}:
        return CTX.as_json_error("bad_request", "match_mode must be contains or exact")
    limit = normalize_limit(args.get("limit"), default=20, minimum=1, maximum=100)
    data = DjangoAdapter.safe_ioc_lookup(query=query, match_mode=match_mode, limit=limit)
    return {"ok": True, **data}


def tool_source_health(args: dict) -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    provider_filter = str(args.get("provider", "")).strip().lower()
    data = DjangoAdapter.provider_registry_inspection(provider_filter=provider_filter or None)
    return {"ok": True, **data}


def tool_provider_registry_inspection(args: dict) -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    provider_filter = str(args.get("provider", "")).strip().lower()
    data = DjangoAdapter.provider_registry_inspection(provider_filter=provider_filter or None)
    return {"ok": True, **data}


def tool_recent_ingestion_run_summary(args: dict) -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    limit = normalize_limit(args.get("limit"), default=10, minimum=1, maximum=50)
    data = DjangoAdapter.recent_ingestion_run_summary(limit=limit)
    return {"ok": True, **data}


def tool_compact_db_schema_introspection(args: dict) -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    _ = args
    data = DjangoAdapter.compact_db_schema_introspection()
    return {"ok": True, **data}


def tool_search_code(args: dict) -> dict:
    query = str(args.get("query", "")).strip()
    if not query:
        return CTX.as_json_error("bad_request", "query is required")

    limit = normalize_limit(args.get("limit"), default=30, minimum=1, maximum=200)
    glob = str(args.get("glob", "*")).strip() or "*"
    target_path = str(args.get("path", ".")).strip() or "."
    try:
        search_root = CTX.safe_path(target_path)
    except ValueError as exc:
        return CTX.as_json_error("invalid_path", str(exc))

    cmd = [
        "rg",
        "--line-number",
        "--column",
        "--no-heading",
        "--color=never",
        "--glob",
        glob,
        query,
        str(search_root),
    ]
    try:
        completed = subprocess.run(
            cmd,
            cwd=CTX.root_dir,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except FileNotFoundError:
        return _search_code_fallback(query=query, path=search_root, limit=limit)
    except subprocess.TimeoutExpired:
        return CTX.as_json_error("timeout", "code search timed out")

    lines = completed.stdout.splitlines()
    matches = []
    for line in lines[:limit]:
        parts = line.split(":", 3)
        if len(parts) != 4:
            continue
        raw_path, line_no, col_no, snippet = parts
        path_obj = Path(raw_path)
        matches.append(
            {
                "path": rel_path(path_obj, CTX.root_dir),
                "line": int(line_no),
                "column": int(col_no),
                "snippet": truncate_text(snippet.strip(), max_chars=220),
            }
        )

    return {
        "ok": True,
        "query": query,
        "path": rel_path(search_root, CTX.root_dir),
        "glob": glob,
        "count": len(matches),
        "truncated": len(lines) > limit,
        "matches": matches,
    }


def _search_code_fallback(query: str, path: Path, limit: int) -> dict:
    pattern = re.compile(query)
    matches = []
    for file_path in path.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in {".py", ".js", ".html", ".css", ".md", ".txt", ".json", ".yml", ".yaml"}:
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for index, line in enumerate(content.splitlines(), start=1):
            hit = pattern.search(line)
            if hit:
                matches.append(
                    {
                        "path": rel_path(file_path, CTX.root_dir),
                        "line": index,
                        "column": hit.start() + 1,
                        "snippet": truncate_text(line.strip(), max_chars=220),
                    }
                )
                if len(matches) >= limit:
                    return {"ok": True, "query": query, "count": len(matches), "truncated": True, "matches": matches}
    return {"ok": True, "query": query, "count": len(matches), "truncated": False, "matches": matches}


def tool_read_file(args: dict) -> dict:
    user_path = str(args.get("path", "")).strip()
    if not user_path:
        return CTX.as_json_error("bad_request", "path is required")
    try:
        file_path = CTX.safe_path(user_path)
    except ValueError as exc:
        return CTX.as_json_error("invalid_path", str(exc))
    if not file_path.exists() or not file_path.is_file():
        return CTX.as_json_error("not_found", "file not found")

    start_line = normalize_limit(args.get("start_line"), default=1, minimum=1, maximum=1_000_000)
    end_line_raw = args.get("end_line")
    if end_line_raw is None:
        end_line = start_line + 199
    else:
        end_line = normalize_limit(end_line_raw, default=start_line + 199, minimum=start_line, maximum=start_line + 399)
    if end_line < start_line:
        end_line = start_line

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return CTX.as_json_error("unsupported", "binary or non-utf8 file")

    selected = lines[start_line - 1 : end_line]
    rendered = "\n".join(selected)
    if len(rendered) > 50_000:
        rendered = rendered[:50_000]

    return {
        "ok": True,
        "path": rel_path(file_path, CTX.root_dir),
        "start_line": start_line,
        "end_line": min(end_line, len(lines)),
        "total_lines": len(lines),
        "content": rendered,
    }


def tool_run_manage_py(args: dict) -> dict:
    command = str(args.get("command", "")).strip()
    if not command:
        return CTX.as_json_error("bad_request", "command is required")
    read_only = bool(args.get("read_only", True))
    if not read_only:
        return CTX.as_json_error("forbidden", "read_only=false is not supported")

    allowed_commands = _allowed_manage_commands()
    if command in DISALLOWED_MANAGE_COMMANDS:
        return CTX.as_json_error("forbidden", f"command not allowed: {command}")
    if command not in allowed_commands:
        return CTX.as_json_error("forbidden", f"command not in allowlist: {command}")

    raw_args = args.get("args", [])
    if raw_args is None:
        raw_args = []
    if not isinstance(raw_args, list):
        return CTX.as_json_error("bad_request", "args must be an array of strings")
    try:
        safe_args = validate_safe_args(raw_args)
    except ValueError as exc:
        return CTX.as_json_error("bad_request", str(exc))

    timeout_seconds = normalize_limit(args.get("timeout_seconds"), default=60, minimum=1, maximum=300)
    cmd = [sys.executable, "manage.py", command, *safe_args]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            cmd,
            cwd=CTX.root_dir,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return CTX.as_json_error("timeout", f"manage.py timed out after {timeout_seconds}s")
    duration_ms = int((time.monotonic() - started) * 1000)
    return {
        "ok": completed.returncode == 0,
        "schema": "ioc.manage_command_result.v1",
        "schema_version": "1.0.0",
        "command": command,
        "args": safe_args,
        "read_only": True,
        "returncode": completed.returncode,
        "duration_ms": duration_ms,
        "stdout": truncate_text(completed.stdout.strip(), max_chars=10000),
        "stderr": truncate_text(completed.stderr.strip(), max_chars=10000),
    }


def _allowed_manage_commands() -> set[str]:
    local_commands_dir = CTX.root_dir / "intel" / "management" / "commands"
    present = {
        p.stem for p in local_commands_dir.glob("*.py") if p.is_file() and p.stem != "__init__"
    }
    return {name for name in READ_ONLY_MANAGE_COMMANDS if name in present or name in {"check", "showmigrations"}}


def tool_run_tests(args: dict) -> dict:
    target = str(args.get("target", "")).strip()
    keyword = str(args.get("keyword", "")).strip()
    max_failures = normalize_limit(args.get("max_failures"), default=1, minimum=1, maximum=20)
    timeout_seconds = normalize_limit(args.get("timeout_seconds"), default=180, minimum=1, maximum=600)

    cmd = [sys.executable, "-m", "pytest", "-q", f"--maxfail={max_failures}"]
    if keyword:
        if len(keyword) > 120:
            return CTX.as_json_error("bad_request", "keyword too long")
        cmd.extend(["-k", keyword])
    if target:
        path_part = target.split("::", 1)[0]
        try:
            target_path = CTX.safe_path(path_part)
        except ValueError as exc:
            return CTX.as_json_error("invalid_path", str(exc))
        node_suffix = target[len(path_part) :]
        cmd.append(f"{target_path}{node_suffix}")

    started = time.monotonic()
    try:
        completed = subprocess.run(
            cmd,
            cwd=CTX.root_dir,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return CTX.as_json_error("timeout", f"pytest timed out after {timeout_seconds}s")

    output = (completed.stdout + "\n" + completed.stderr).strip()
    duration_ms = int((time.monotonic() - started) * 1000)
    summary_line = ""
    for line in reversed(output.splitlines()):
        if " passed" in line or " failed" in line or " error" in line:
            summary_line = line.strip()
            break

    return {
        "ok": completed.returncode == 0,
        "returncode": completed.returncode,
        "duration_ms": duration_ms,
        "summary": summary_line,
        "output": truncate_text(output, max_chars=15000),
    }


def tool_explain_traceback(args: dict) -> dict:
    tb = str(args.get("traceback", "")).strip()
    if not tb:
        return CTX.as_json_error("bad_request", "traceback is required")

    frames = []
    exception_type = ""
    exception_message = ""

    for line in tb.splitlines():
        frame_match = FRAME_RE.match(line)
        if frame_match:
            frames.append(
                {
                    "file": frame_match.group(1),
                    "line": int(frame_match.group(2)),
                    "function": frame_match.group(3),
                }
            )

    for line in reversed(tb.splitlines()):
        exc_match = TRACEBACK_EXC_RE.match(line.strip())
        if exc_match:
            exception_type = exc_match.group(1)
            exception_message = exc_match.group(2)
            break

    likely_causes = _likely_causes(exception_type, exception_message)
    return {
        "ok": True,
        "exception_type": exception_type or None,
        "exception_message": exception_message or None,
        "frame_count": len(frames),
        "top_frames": frames[-5:],
        "likely_causes": likely_causes,
    }


def _likely_causes(exception_type: str, exception_message: str) -> list[str]:
    msg_lower = exception_message.lower()
    if exception_type.endswith("OperationalError"):
        return ["Database connectivity/config issue", "Pending migrations or schema mismatch"]
    if exception_type.endswith("IntegrityError"):
        return ["Unique/foreign key constraint violation", "Duplicate ingest row in one transaction"]
    if exception_type.endswith("DoesNotExist"):
        return ["Query expected exactly one record but none matched"]
    if exception_type.endswith("MultipleObjectsReturned"):
        return ["Query expected one record but multiple rows matched"]
    if exception_type.endswith("KeyError"):
        return ["Missing dict key in provider payload normalization"]
    if exception_type.endswith("TypeError"):
        return ["Unexpected data type passed to function", "None used where a value is required"]
    if exception_type.endswith("ValueError"):
        return ["Invalid input value or parse failure"]
    if "connection refused" in msg_lower or "could not connect" in msg_lower:
        return ["External provider/network endpoint unavailable", "Service host/port misconfiguration"]
    return ["Inspect the deepest project frame and validate input assumptions around that call"]


def _django_adapter():
    from mcp_server.adapters import DjangoAdapter

    return DjangoAdapter
