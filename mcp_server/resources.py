from __future__ import annotations

from collections import defaultdict

from mcp_server.context import CTX
from mcp_server.utils import rel_path, to_compact_json


RESOURCE_ITEMS = [
    {
        "uri": "ioc://project/overview",
        "name": "project overview",
        "description": "High-level IOC project summary.",
        "mimeType": "application/json",
    },
    {
        "uri": "ioc://project/db-schema-summary",
        "name": "db schema summary",
        "description": "Compact summary of key database tables and fields.",
        "mimeType": "application/json",
    },
    {
        "uri": "ioc://project/provider-status-summary",
        "name": "provider status summary",
        "description": "Provider enablement and most recent run status.",
        "mimeType": "application/json",
    },
    {
        "uri": "ioc://project/file-map",
        "name": "file map",
        "description": "Compact code map for major directories and files.",
        "mimeType": "application/json",
    },
    {
        "uri": "ioc://project/recent-errors-summary",
        "name": "recent errors summary",
        "description": "Recent provider and ingestion failures.",
        "mimeType": "application/json",
    },
    {
        "uri": "ioc://project/recent-ingestion-run-summary",
        "name": "recent ingestion run summary",
        "description": "Compact recent ingestion run summary.",
        "mimeType": "application/json",
    },
]


def list_resources() -> dict:
    return {"resources": RESOURCE_ITEMS}


def read_resource(uri: str) -> dict:
    handlers = {
        "ioc://project/overview": _project_overview,
        "ioc://project/db-schema-summary": _db_schema_summary,
        "ioc://project/provider-status-summary": _provider_status_summary,
        "ioc://project/file-map": _file_map,
        "ioc://project/recent-errors-summary": _recent_errors_summary,
        "ioc://project/recent-ingestion-run-summary": _recent_ingestion_run_summary,
    }
    handler = handlers.get(uri)
    if handler is None:
        raise ValueError(f"unknown resource uri: {uri}")

    payload = handler()
    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": "application/json",
                "text": to_compact_json(payload),
            }
        ]
    }


def _project_overview() -> dict:
    CTX.ensure_django()
    from django.conf import settings

    from intel.models import IntelIOC

    total_iocs = IntelIOC.objects.count()
    source_counts = defaultdict(int)
    for row in IntelIOC.objects.values("source_name"):
        source_counts[row["source_name"] or "unknown"] += 1

    commands_dir = CTX.root_dir / "intel" / "management" / "commands"
    commands = sorted(
        p.stem for p in commands_dir.glob("*.py") if p.is_file() and p.stem != "__init__"
    )
    return {
        "project_root": str(CTX.root_dir),
        "django_settings_module": "config.settings",
        "database_engine": settings.DATABASES["default"]["ENGINE"],
        "total_iocs": total_iocs,
        "ioc_sources": [{"source_name": name, "count": count} for name, count in sorted(source_counts.items())],
        "management_commands": commands,
        "installed_apps": list(settings.INSTALLED_APPS),
    }


def _db_schema_summary() -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    return DjangoAdapter.compact_db_schema_introspection()


def _provider_status_summary() -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    return DjangoAdapter.provider_registry_inspection(provider_filter=None)


def _file_map() -> dict:
    tracked_dirs = ["config", "intel", "docs", "testing", "mcp_server"]
    directories: list[dict] = []
    for directory in tracked_dirs:
        base = CTX.root_dir / directory
        if not base.exists():
            continue
        file_paths = [p for p in base.rglob("*") if p.is_file()]
        py_files = [p for p in file_paths if p.suffix == ".py"]
        sample = [rel_path(p, CTX.root_dir) for p in sorted(py_files)[:25]]
        directories.append(
            {
                "path": directory,
                "total_files": len(file_paths),
                "python_files": len(py_files),
                "sample_python_paths": sample,
            }
        )
    return {"directories": directories}


def _recent_errors_summary() -> dict:
    CTX.ensure_django()
    from django.db.models import Q

    from intel.models import IngestionRun, ProviderRun

    provider_failures = list(
        ProviderRun.objects.filter(Q(status="failure") | Q(status="partial"))
        .order_by("-started_at", "-id")
        .values(
            "provider_name",
            "run_type",
            "status",
            "started_at",
            "completed_at",
            "last_error_message",
        )[:20]
    )
    ingestion_failures = list(
        IngestionRun.objects.exclude(error_summary="")
        .order_by("-started_at", "-id")
        .values(
            "status",
            "trigger",
            "requested_provider",
            "started_at",
            "finished_at",
            "error_summary",
        )[:20]
    )
    return {
        "provider_failures": provider_failures,
        "ingestion_failures": ingestion_failures,
    }


def _recent_ingestion_run_summary() -> dict:
    CTX.ensure_django()
    DjangoAdapter = _django_adapter()
    return DjangoAdapter.recent_ingestion_run_summary(limit=10)


def _django_adapter():
    from mcp_server.adapters import DjangoAdapter

    return DjangoAdapter
