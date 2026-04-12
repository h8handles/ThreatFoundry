from django.core.management.base import BaseCommand, CommandError

from intel.models import IntelIOC
from intel.services.provider_registry import get_provider_spec
from intel.services.provider_runs import ProviderRunRecorder
from intel.services.virustotal import (
    UnsupportedVirusTotalLookup,
    VirusTotalNotFound,
    enrich_ioc_record,
    throttle_request,
)


class Command(BaseCommand):
    """Enrich existing local IOCs with VirusTotal context."""

    help = (
        "Fetch VirusTotal context for stored IOCs and merge the enrichment into "
        "the local platform fields."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=25,
            help="Maximum number of local IOCs to enrich during this run.",
        )
        parser.add_argument(
            "--source",
            action="append",
            default=[],
            help="Optional source filter. Repeat the flag to enrich multiple sources.",
        )
        parser.add_argument(
            "--value-type",
            action="append",
            default=[],
            help="Optional IOC type filter. Repeat the flag to target multiple types.",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Refresh records that already have VirusTotal enrichment stored.",
        )
        parser.add_argument(
            "--timeout",
            type=int,
            default=30,
            help="HTTP timeout in seconds for each VirusTotal request.",
        )
        parser.add_argument(
            "--throttle-seconds",
            type=float,
            default=16.0,
            help=(
                "Delay between VirusTotal requests. The public VT API is quota-limited, "
                "so the default stays conservative."
            ),
        )

    def handle(self, *args, **options):
        limit = max(options["limit"], 1)
        timeout = options["timeout"]
        throttle_seconds = max(options["throttle_seconds"], 0.0)
        force = options["force"]
        verbosity = options["verbosity"]
        provider_spec = get_provider_spec("virustotal")
        enabled_state = provider_spec.is_enabled() if provider_spec else None
        recorder = ProviderRunRecorder.start(
            provider_name="virustotal",
            run_type="enrichment",
            enabled_state=enabled_state,
            details={
                "limit": limit,
                "sources": options["source"],
                "value_types": options["value_type"],
                "force": force,
                "timeout": timeout,
                "throttle_seconds": throttle_seconds,
            },
        )

        if provider_spec and not enabled_state:
            message = "VirusTotal is disabled or missing required configuration."
            recorder.mark_skipped(error_message=message)
            self.stdout.write(self.style.WARNING(message))
            return

        queryset = IntelIOC.objects.all()
        if options["source"]:
            queryset = queryset.filter(source_name__in=options["source"])
        if options["value_type"]:
            queryset = queryset.filter(value_type__in=options["value_type"])
        candidate_records = list(
            queryset.order_by("-last_ingested_at", "-created_at", "-id")
        )
        if force:
            records = candidate_records[:limit]
        else:
            records = [
                record
                for record in candidate_records
                if "virustotal" not in (record.enrichment_payloads or {})
            ][:limit]
        if not records:
            recorder.mark_skipped(
                error_message="No IOC records matched the VirusTotal enrichment scope.",
                records_fetched=0,
                records_updated=0,
                records_skipped=0,
            )
            self.stdout.write(
                self.style.WARNING("No IOC records matched the VirusTotal enrichment scope.")
            )
            return

        if verbosity >= 1:
            estimated_wait = max(len(records) - 1, 0) * throttle_seconds
            self.stdout.write(
                "Starting VirusTotal enrichment "
                f"for {len(records)} IOC(s); throttle={throttle_seconds:.1f}s; "
                f"estimated wait time~{estimated_wait:.1f}s."
            )

        updated = 0
        skipped = 0
        not_found = 0
        unsupported = 0

        for index, record in enumerate(records, start=1):
            if verbosity >= 1:
                self.stdout.write(
                    f"[{index}/{len(records)}] Looking up {record.value_type} {record.value}"
                )
            try:
                changed = enrich_ioc_record(record, force=force, timeout=timeout)
            except UnsupportedVirusTotalLookup:
                unsupported += 1
                if verbosity >= 1:
                    self.stdout.write(
                        self.style.WARNING(
                            f"[{index}/{len(records)}] Skipped unsupported IOC type {record.value_type}."
                        )
                    )
                continue
            except VirusTotalNotFound:
                not_found += 1
                if verbosity >= 1:
                    self.stdout.write(
                        self.style.WARNING(
                            f"[{index}/{len(records)}] VirusTotal has no report for {record.value}."
                        )
                    )
                continue
            except Exception as exc:
                recorder.mark_failure(
                    error_message=f"VirusTotal enrichment failed for IOC {record.pk} ({record.value}): {exc}",
                    error_type=type(exc).__name__,
                    records_fetched=len(records),
                    records_updated=updated,
                    records_skipped=skipped + not_found + unsupported,
                    details={
                        "failed_record_id": record.pk,
                        "failed_record_value": record.value,
                    },
                )
                raise CommandError(
                    f"VirusTotal enrichment failed for IOC {record.pk} ({record.value}): {exc}"
                ) from exc

            if changed:
                updated += 1
                if verbosity >= 1:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"[{index}/{len(records)}] Enriched IOC {record.pk}."
                        )
                    )
            else:
                skipped += 1
                if verbosity >= 1:
                    self.stdout.write(
                        f"[{index}/{len(records)}] IOC {record.pk} already had VirusTotal enrichment."
                    )

            if index < len(records):
                if throttle_seconds > 0 and verbosity >= 1:
                    self.stdout.write(
                        f"[{index}/{len(records)}] Waiting {throttle_seconds:.1f}s to respect VirusTotal quota..."
                    )
                throttle_request(throttle_seconds)

        total_skipped = skipped + not_found + unsupported
        if updated and total_skipped:
            recorder.mark_partial(
                records_fetched=len(records),
                records_created=0,
                records_updated=updated,
                records_skipped=total_skipped,
                details={
                    "not_found": not_found,
                    "unsupported": unsupported,
                    "already_enriched": skipped,
                },
            )
        elif updated:
            recorder.mark_success(
                records_fetched=len(records),
                records_created=0,
                records_updated=updated,
                records_skipped=0,
            )
        else:
            recorder.mark_skipped(
                records_fetched=len(records),
                records_created=0,
                records_updated=0,
                records_skipped=total_skipped,
                details={
                    "not_found": not_found,
                    "unsupported": unsupported,
                    "already_enriched": skipped,
                },
            )

        self.stdout.write(
            self.style.SUCCESS(
                "VirusTotal enrichment complete "
                f"(updated={updated}, skipped={skipped}, not_found={not_found}, unsupported={unsupported})."
            )
        )
