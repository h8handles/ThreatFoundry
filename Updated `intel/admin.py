from django.contrib import admin

from intel.models import IngestionRun, IntelIOC, ProviderRun, ProviderRunDetail


@admin.register(IntelIOC)
class IntelIOCAdmin(admin.ModelAdmin):
    list_display = (
        "value",
        "value_type",
        "source_name",
        "threat_type",
        "malware_family",
        "confidence_level",
        "last_seen",
    )
    list_filter = ("source_name", "value_type", "threat_type", "malware_family")
    search_fields = ("value", "source_record_id", "reporter", "malware_family")


@admin.register(ProviderRun)
class ProviderRunAdmin(admin.ModelAdmin):
    list_display = (
        "provider_name",
        "run_type",
        "status",
        "enabled_state",
        "started_at",
        "completed_at",
        "records_fetched",
        "records_created",
        "records_updated",
        "records_skipped",
    )
    list_filter = ("provider_name", "run_type", "status", "enabled_state")
    search_fields = ("provider_name", "last_error_message")
    readonly_fields = (
        "provider_name",
        "run_type",
        "status",
        "enabled_state",
        "started_at",
        "completed_at",
        "last_error_message",
        "records_fetched",
        "records_created",
        "records_updated",
        "records_skipped",
        "details",
    )


class ProviderRunDetailInline(admin.TabularInline):
    model = ProviderRunDetail
    extra = 0
    can_delete = False
    fields = (
        "provider_name",
        "run_type",
        "status",
        "enabled_state",
        "started_at",
        "finished_at",
        "records_fetched",
        "records_created",
        "records_updated",
        "records_skipped",
        "error_summary",
    )
    readonly_fields = fields


@admin.register(IngestionRun)
class IngestionRunAdmin(admin.ModelAdmin):
    list_display = (
        "started_at",
        "status",
        "trigger",
        "requested_provider",
        "dry_run",
        "feed_refreshed",
        "providers_total",
        "providers_failed",
        "records_created",
        "records_updated",
        "records_skipped",
    )
    list_filter = ("status", "trigger", "dry_run", "feed_refreshed")
    search_fields = ("requested_provider", "requested_since", "error_summary")
    readonly_fields = (
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
        "details",
    )
    inlines = [ProviderRunDetailInline]


@admin.register(ProviderRunDetail)
class ProviderRunDetailAdmin(admin.ModelAdmin):
    list_display = (
        "provider_name",
        "run_type",
        "status",
        "enabled_state",
        "started_at",
        "finished_at",
        "records_fetched",
        "records_created",
        "records_updated",
        "records_skipped",
    )
    list_filter = ("provider_name", "run_type", "status", "enabled_state")
    search_fields = ("provider_name", "error_summary")
    readonly_fields = (
        "ingestion_run",
        "provider_name",
        "run_type",
        "status",
        "enabled_state",
        "started_at",
        "finished_at",
        "records_fetched",
        "records_created",
        "records_updated",
        "records_skipped",
        "error_summary",
        "details",
    )
