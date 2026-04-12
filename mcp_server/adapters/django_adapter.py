from __future__ import annotations

class DjangoAdapter:
    SCHEMA_VERSION = "1.0.0"

    @classmethod
    def safe_ioc_lookup(cls, *, query: str, match_mode: str, limit: int) -> dict:
        from django.db.models import Q

        from intel.models import IntelIOC

        base = {
            "schema": "ioc.lookup_ioc.v1",
            "schema_version": cls.SCHEMA_VERSION,
            "query": query,
            "match_mode": match_mode,
            "limit": limit,
        }
        if match_mode == "exact":
            queryset = IntelIOC.objects.filter(
                Q(value__iexact=query)
                | Q(source_record_id__iexact=query)
                | Q(malware_family__iexact=query)
                | Q(threat_type__iexact=query)
            )
        else:
            queryset = IntelIOC.objects.filter(
                Q(value__icontains=query)
                | Q(source_record_id__icontains=query)
                | Q(malware_family__icontains=query)
                | Q(threat_type__icontains=query)
                | Q(tags__icontains=query)
            )

        rows = []
        for row in queryset.order_by("-last_seen", "-updated_at")[:limit]:
            rows.append(
                {
                    "id": row.id,
                    "source_name": row.source_name,
                    "source_record_id": row.source_record_id,
                    "value": row.value,
                    "value_type": row.value_type,
                    "threat_type": row.threat_type,
                    "malware_family": row.malware_family,
                    "confidence_level": row.confidence_level,
                    "last_seen": row.last_seen,
                    "updated_at": row.updated_at,
                }
            )
        return {**base, "count": len(rows), "results": rows}

    @classmethod
    def provider_registry_inspection(cls, *, provider_filter: str | None = None) -> dict:
        from intel.models import ProviderRun
        from intel.services.provider_registry import get_provider_availabilities

        latest_by_provider: dict[str, ProviderRun] = {}
        for run in ProviderRun.objects.order_by("-started_at", "-id")[:300]:
            if run.provider_name not in latest_by_provider:
                latest_by_provider[run.provider_name] = run

        providers = []
        for availability in get_provider_availabilities():
            if provider_filter and availability.key != provider_filter:
                continue
            latest = latest_by_provider.get(availability.key)
            providers.append(
                {
                    "provider": availability.key,
                    "label": availability.label,
                    "category": availability.category,
                    "enabled": availability.enabled,
                    "missing_env_vars": list(availability.missing_env_vars),
                    "note": availability.note,
                    "last_run": None
                    if latest is None
                    else {
                        "run_type": latest.run_type,
                        "status": latest.status,
                        "started_at": latest.started_at,
                        "completed_at": latest.completed_at,
                        "records_fetched": latest.records_fetched,
                        "records_created": latest.records_created,
                        "records_updated": latest.records_updated,
                        "records_skipped": latest.records_skipped,
                        "last_error_message": latest.last_error_message,
                    },
                }
            )
        return {
            "schema": "ioc.provider_registry.v1",
            "schema_version": cls.SCHEMA_VERSION,
            "provider_filter": provider_filter,
            "count": len(providers),
            "providers": providers,
        }

    @classmethod
    def recent_ingestion_run_summary(cls, *, limit: int) -> dict:
        from intel.models import IngestionRun

        runs = list(
            IngestionRun.objects.order_by("-started_at", "-id")
            .values(
                "id",
                "status",
                "trigger",
                "requested_provider",
                "requested_since",
                "timeout_seconds",
                "dry_run",
                "feed_refreshed",
                "started_at",
                "finished_at",
                "providers_total",
                "providers_succeeded",
                "providers_failed",
                "providers_skipped",
                "records_created",
                "records_updated",
                "records_skipped",
                "error_summary",
            )[:limit]
        )
        return {
            "schema": "ioc.ingestion_runs.v1",
            "schema_version": cls.SCHEMA_VERSION,
            "count": len(runs),
            "runs": runs,
        }

    @classmethod
    def compact_db_schema_introspection(cls) -> dict:
        from intel.models import IngestionRun, IntelIOC, ProviderRun

        models = [IntelIOC, ProviderRun, IngestionRun]
        table_summaries = []
        for model in models:
            fields = []
            indexed_fields: list[str] = []
            for field in model._meta.fields:
                if getattr(field, "db_index", False):
                    indexed_fields.append(field.name)
                fields.append(
                    {
                        "name": field.name,
                        "type": field.get_internal_type(),
                        "null": bool(getattr(field, "null", False)),
                        "primary_key": bool(getattr(field, "primary_key", False)),
                    }
                )
            unique_constraints = []
            for constraint in model._meta.constraints:
                if hasattr(constraint, "fields"):
                    unique_constraints.append(
                        {
                            "name": getattr(constraint, "name", ""),
                            "fields": list(getattr(constraint, "fields", ()) or ()),
                        }
                    )
            table_summaries.append(
                {
                    "model": model.__name__,
                    "db_table": model._meta.db_table,
                    "field_count": len(fields),
                    "fields": fields,
                    "db_indexes": sorted(set(indexed_fields)),
                    "unique_constraints": unique_constraints,
                }
            )
        return {
            "schema": "ioc.db_schema_compact.v1",
            "schema_version": cls.SCHEMA_VERSION,
            "tables": table_summaries,
        }
