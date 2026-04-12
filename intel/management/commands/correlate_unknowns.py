from django.core.management.base import BaseCommand, CommandError

from intel.services.correlation import correlate_unknown_iocs


class Command(BaseCommand):
    help = "Correlate partially unknown IOCs against locally stored IOC and enrichment evidence."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            help="Maximum number of unknown IOC records to process.",
        )

    def handle(self, *args, **options):
        limit = options.get("limit")
        if limit is not None and limit <= 0:
            raise CommandError("--limit must be greater than zero")

        result = correlate_unknown_iocs(limit=limit)

        for item in result["results"]:
            state = "promoted" if item["promoted"] else "kept-unknown"
            self.stdout.write(
                f"IOC {item['pk']} {item['value_type']} {item['value']} "
                f"score={item['score']} state={state}"
            )
            if item["likely_malware_family"] or item["likely_threat_type"]:
                self.stdout.write(
                    "  likely="
                    f"family:{item['likely_malware_family'] or 'N/A'} "
                    f"threat:{item['likely_threat_type'] or 'N/A'}"
                )
            for reason in item["reasons"]:
                self.stdout.write(f"  reason: {reason}")

        self.stdout.write(f"processed_count: {result['processed']}")
        self.stdout.write(f"skipped_count: {result['skipped']}")
        self.stdout.write(f"promoted_count: {result['promoted']}")
