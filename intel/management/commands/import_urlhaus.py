from django.core.management.base import BaseCommand, CommandError

from intel.services.ingestion import normalize_urlhaus_record, upsert_iocs
from intel.services.provider_registry import get_provider_spec
from intel.services.provider_runs import ProviderRunRecorder
from intel.services.urlhaus import fetch_recent_urlhaus_iocs


def extract_urlhaus_records(payload) -> list[dict]:
    if isinstance(payload, list):
        return [record for record in payload if isinstance(record, dict)]

    if isinstance(payload, dict):
        for key in ("urls", "data", "results"):
            records = payload.get(key)
            if isinstance(records, list):
                return [record for record in records if isinstance(record, dict)]

    raise CommandError("URLHaus response did not include a valid record list.")


class Command(BaseCommand):
    help = "Fetch recent URLHaus malicious URLs and upsert them into the local IOC database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--timeout",
            type=int,
            default=30,
            help="HTTP timeout in seconds for the URLHaus request.",
        )

    def handle(self, *args, **options):
        timeout = options["timeout"]
        provider_spec = get_provider_spec("urlhaus")
        enabled_state = provider_spec.is_enabled() if provider_spec else None
        recorder = ProviderRunRecorder.start(
            provider_name="urlhaus",
            run_type="ingest",
            enabled_state=enabled_state,
            details={"timeout": timeout},
        )

        if provider_spec and not enabled_state:
            message = "URLhaus is disabled by configuration."
            recorder.mark_skipped(error_message=message)
            self.stdout.write(self.style.WARNING(message))
            return

        try:
            payload = fetch_recent_urlhaus_iocs(timeout=timeout)
        except Exception as exc:
            recorder.mark_failure(
                error_message=f"URLHaus fetch failed: {exc}",
                error_type=type(exc).__name__,
            )
            raise CommandError(f"URLHaus fetch failed: {exc}") from exc

        try:
            records = extract_urlhaus_records(payload)
        except CommandError as exc:
            recorder.mark_failure(error_message=str(exc), error_type=type(exc).__name__)
            raise

        result = upsert_iocs(
            records,
            normalizer=normalize_urlhaus_record,
            provider_name="urlhaus",
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
                "URLHaus import complete "
                f"(created={result.created}, updated={result.updated}, skipped={result.skipped})."
            )
        )
