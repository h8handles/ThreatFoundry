from django.core.management.base import BaseCommand, CommandError

from intel.models import IngestionRun, ProviderRunDetail
from intel.services.refresh_pipeline import run_refresh_pipeline


class Command(BaseCommand):
    help = (
        "Refresh all enabled intel providers, record per-run history, and refresh "
        "the dashboard/feed view of the latest data."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--provider",
            type=str,
            help="Run only one provider by key, such as threatfox or virustotal.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            help="HTTP timeout in seconds to pass to provider requests.",
        )
        parser.add_argument(
            "--since",
            type=str,
            help="ISO datetime or relative window like 24h or 7d.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Fetch and evaluate work without writing database changes.",
        )
        parser.add_argument(
            "--no-feed-refresh",
            action="store_true",
            help="Skip the post-ingestion dashboard/feed refresh snapshot step.",
        )
        parser.add_argument(
            "--trigger",
            type=str,
            default="manual",
            help="Internal trigger label for run tracking.",
        )

    def handle(self, *args, **options):
        try:
            result = run_refresh_pipeline(
                provider_name=options.get("provider"),
                timeout=options.get("timeout"),
                since=options.get("since"),
                dry_run=options.get("dry_run", False),
                refresh_feed=not options.get("no_feed_refresh", False),
                trigger=options.get("trigger") or "manual",
            )
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        run = result.run

        for provider_result in result.provider_results:
            style = self.style.SUCCESS
            if provider_result.status == ProviderRunDetail.Status.FAILURE:
                style = self.style.ERROR
            elif provider_result.status in {
                ProviderRunDetail.Status.SKIPPED,
                ProviderRunDetail.Status.PARTIAL,
            }:
                style = self.style.WARNING

            self.stdout.write(
                style(
                    f"{provider_result.provider_name}: {provider_result.status} "
                    f"(fetched={provider_result.records_fetched}, "
                    f"created={provider_result.records_created}, "
                    f"updated={provider_result.records_updated}, "
                    f"skipped={provider_result.records_skipped})"
                )
            )
            if provider_result.error_summary:
                self.stdout.write(style(f"  error: {provider_result.error_summary}"))
            self._write_provider_diagnostics(provider_result)

        summary_style = self.style.SUCCESS
        if run.status == IngestionRun.Status.FAILURE:
            summary_style = self.style.ERROR
        elif run.status == IngestionRun.Status.PARTIAL:
            summary_style = self.style.WARNING

        self.stdout.write(
            summary_style(
                "refresh_intel complete "
                f"(status={run.status}, providers={run.providers_total}, "
                f"failed={run.providers_failed}, created={run.records_created}, "
                f"updated={run.records_updated}, skipped={run.records_skipped}, "
                f"run_id={run.pk})."
            )
        )

        if run.status == IngestionRun.Status.FAILURE and run.providers_total:
            raise CommandError(run.error_summary or "All selected providers failed.")

    def _write_provider_diagnostics(self, provider_result):
        details = provider_result.details or {}
        skip_breakdown = details.get("skip_breakdown") or {}
        if skip_breakdown:
            breakdown_parts = [
                f"{label}={int(skip_breakdown.get(key) or 0)}"
                for key, label in (
                    ("already_enriched", "already enriched"),
                    ("unsupported_lookup_type", "unsupported lookup type"),
                    ("not_found", "VT not found"),
                    ("no_changes_after_enrichment", "no changes after enrichment"),
                    ("error", "error"),
                )
            ]
            self.stdout.write(f"  skip breakdown: {', '.join(breakdown_parts)}")

        record_diagnostics = details.get("record_diagnostics") or []
        for item in record_diagnostics:
            reason = item.get("skip_reason") or "updated"
            lookup = "supported" if item.get("lookup_supported") else "unsupported"
            db_changed = "yes" if item.get("db_changed") else "no"
            self.stdout.write(
                "  IOC "
                f"{item.get('ioc_id')} "
                f"value={item.get('value')} "
                f"type={item.get('value_type')} "
                f"already_enriched={item.get('already_enriched')} "
                f"lookup={lookup} "
                f"db_changed={db_changed} "
                f"reason={reason}"
            )
            detail = item.get("skip_detail") or item.get("lookup_support_detail") or ""
            if detail:
                self.stdout.write(f"    detail: {detail}")
