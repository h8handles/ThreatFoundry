from django.core.management.base import BaseCommand, CommandError

from intel.services.alienvault import fetch_otx_iocs
from intel.services.ingestion import normalize_alienvault_record, upsert_iocs
from intel.services.provider_registry import get_provider_spec
from intel.services.provider_runs import ProviderRunRecorder


def extract_otx_records(payload) -> list[dict]:
    """Accept the common OTX payload shapes and return a plain record list."""
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]

    if isinstance(payload, dict):
        for key in ("results", "data", "indicators"):
            records = payload.get(key)
            if isinstance(records, list):
                return [record for record in records if isinstance(record, dict)]

    raise CommandError("AlienVault response did not include a valid record list.")


class Command(BaseCommand):
    """Import recent AlienVault OTX IOCs into the database."""

    help = "Fetch AlienVault OTX IOCs and upsert them into the local IOC database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=1,
            help="Number of recent days to request from AlienVault OTX.",
        )

    def handle(self, *args, **options):
        days = options["days"]
        provider_spec = get_provider_spec("alienvault")
        enabled_state = provider_spec.is_enabled() if provider_spec else None
        recorder = ProviderRunRecorder.start(
            provider_name="alienvault",
            run_type="ingest",
            enabled_state=enabled_state,
            details={"days": days},
        )

        if provider_spec and not enabled_state:
            message = "AlienVault OTX is disabled or missing required configuration."
            recorder.mark_skipped(error_message=message)
            self.stdout.write(self.style.WARNING(message))
            return

        try:
            payload = fetch_otx_iocs(days=days)
        except Exception as exc:
            recorder.mark_failure(
                error_message=f"AlienVault fetch failed: {exc}",
                error_type=type(exc).__name__,
            )
            raise CommandError(f"AlienVault fetch failed: {exc}") from exc

        try:
            records = extract_otx_records(payload)
        except CommandError as exc:
            recorder.mark_failure(error_message=str(exc), error_type=type(exc).__name__)
            raise

        result = upsert_iocs(
            records,
            normalizer=normalize_alienvault_record,
            provider_name="alienvault",
        )
        finalize = recorder.mark_partial if result.skipped else recorder.mark_success
        finalize(
            records_fetched=len(records),
            records_created=result.created,
            records_updated=result.updated,
            records_skipped=result.skipped,
        )

        self.stdout.write(
            self.style.SUCCESS(
                "AlienVault import complete "
                f"(created={result.created}, updated={result.updated}, skipped={result.skipped})."
            )
        )
