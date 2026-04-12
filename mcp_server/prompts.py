from __future__ import annotations

from mcp_server.utils import to_compact_json


PROMPT_ITEMS = [
    {
        "name": "investigate_ioc",
        "description": "Investigate one IOC end-to-end with source and enrichment context.",
        "arguments": [
            {"name": "ioc_value", "required": True},
            {"name": "focus", "required": False},
        ],
    },
    {
        "name": "fix_ingestion_bug",
        "description": "Debug and fix an IOC ingestion bug in provider pipelines.",
        "arguments": [
            {"name": "provider", "required": False},
            {"name": "error", "required": True},
        ],
    },
    {
        "name": "improve_dashboard",
        "description": "Plan and implement dashboard improvements.",
        "arguments": [{"name": "objective", "required": True}],
    },
    {
        "name": "improve_chatbot",
        "description": "Plan and implement analyst chatbot improvements.",
        "arguments": [{"name": "objective", "required": True}],
    },
]


def list_prompts() -> dict:
    return {"prompts": PROMPT_ITEMS}


def get_prompt(name: str, arguments: dict | None) -> dict:
    args = arguments or {}
    handlers = {
        "investigate_ioc": _investigate_ioc_prompt,
        "fix_ingestion_bug": _fix_ingestion_bug_prompt,
        "improve_dashboard": _improve_dashboard_prompt,
        "improve_chatbot": _improve_chatbot_prompt,
    }
    handler = handlers.get(name)
    if handler is None:
        raise ValueError(f"unknown prompt: {name}")

    text = handler(args)
    return {
        "description": next(item["description"] for item in PROMPT_ITEMS if item["name"] == name),
        "messages": [{"role": "user", "content": {"type": "text", "text": text}}],
    }


def _investigate_ioc_prompt(args: dict) -> str:
    ioc_value = str(args.get("ioc_value", "")).strip()
    focus = str(args.get("focus", "")).strip()
    plan = {
        "task": "investigate_ioc",
        "ioc_value": ioc_value,
        "focus": focus or None,
        "steps": [
            "Read ioc://project/overview and ioc://project/provider-status-summary resources.",
            "Call lookup_ioc with match_mode=contains for the IOC value.",
            "Call source_health for providers tied to matched rows.",
            "Use read_file/search_code to inspect ingestion and dashboard code paths involved.",
            "Return concise findings: IOC context, likely risk, data quality issues, and recommended next action.",
        ],
    }
    return to_compact_json(plan)


def _fix_ingestion_bug_prompt(args: dict) -> str:
    provider = str(args.get("provider", "")).strip()
    error = str(args.get("error", "")).strip()
    plan = {
        "task": "fix_ingestion_bug",
        "provider": provider or None,
        "error": error,
        "steps": [
            "Read ioc://project/recent-errors-summary and ioc://project/db-schema-summary.",
            "Use explain_traceback on the provided traceback/error excerpt.",
            "Inspect provider-specific service + intel/services/ingestion.py with search_code/read_file.",
            "Run a bounded command via run_manage_py or run_tests to reproduce.",
            "Implement minimal fix and verify with targeted tests.",
        ],
    }
    return to_compact_json(plan)


def _improve_dashboard_prompt(args: dict) -> str:
    objective = str(args.get("objective", "")).strip()
    plan = {
        "task": "improve_dashboard",
        "objective": objective,
        "steps": [
            "Read ioc://project/file-map and project overview resources.",
            "Inspect intel/views.py, intel/services/dashboard.py, template and static dashboard assets.",
            "Define measurable UX/perf improvements with minimal regression risk.",
            "Apply focused code changes and run relevant tests.",
            "Summarize behavior changes and follow-up validation items.",
        ],
    }
    return to_compact_json(plan)


def _improve_chatbot_prompt(args: dict) -> str:
    objective = str(args.get("objective", "")).strip()
    plan = {
        "task": "improve_chatbot",
        "objective": objective,
        "steps": [
            "Read project overview and provider status resources for context.",
            "Inspect chatbot modules: intel/views_chat.py, intel/services/chatbot.py, templates/static assets.",
            "Define safe prompt/context changes and error handling updates.",
            "Run targeted tests (chatbot + affected integration points).",
            "Report final changes, risks, and next tuning opportunities.",
        ],
    }
    return to_compact_json(plan)
