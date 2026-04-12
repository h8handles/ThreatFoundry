from django.core.management.base import BaseCommand, CommandError

from intel.services.ingestion import upsert_iocs
from intel.services.provider_registry import get_provider_spec
from intel.services.provider_runs import ProviderRunRecorder
from intel.services.threatfox import fetch_threatfox_iocs


class Command(BaseCommand):
    """Import recent ThreatFox IOCs into the database."""

    help = "Fetch ThreatFox IOCs and upsert them into the local IOC database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=1,
            help="Number of recent days to request from ThreatFox.",
        )

    def handle(self, *args, **options):
        days = options["days"]
        provider_spec = get_provider_spec("threatfox")
        enabled_state = provider_spec.is_enabled() if provider_spec else None
        recorder = ProviderRunRecorder.start(
            provider_name="threatfox",
            run_type="ingest",
            enabled_state=enabled_state,
            details={"days": days},
        )

        if provider_spec and not enabled_state:
            message = "ThreatFox is disabled or missing required configuration."
            recorder.mark_skipped(error_message=message)
            self.stdout.write(self.style.WARNING(message))
            return

        try:
            # Step 1: download raw ThreatFox data.
            payload = fetch_threatfox_iocs(days=days)
        except Exception as exc:
            recorder.mark_failure(
                error_message=f"ThreatFox fetch failed: {exc}",
                error_type=type(exc).__name__,
            )
            raise CommandError(f"ThreatFox fetch failed: {exc}") from exc

        records = payload.get("data") or []
        if not isinstance(records, list):
            recorder.mark_failure(
                error_message="ThreatFox response did not include a valid data list.",
                error_type="CommandError",
            )
            raise CommandError("ThreatFox response did not include a valid data list.")

        # Step 2: normalize and save the records.
        result = upsert_iocs(records, provider_name="threatfox")
        finalize = recorder.mark_partial if result.skipped else recorder.mark_success
        finalize(
            records_fetched=len(records),
            records_created=result.created,
            records_updated=result.updated,
            records_skipped=result.skipped,
        )

        self.stdout.write(
            self.style.SUCCESS(
                "ThreatFox import complete "
                f"(created={result.created}, updated={result.updated}, skipped={result.skipped})."
            )
        )
