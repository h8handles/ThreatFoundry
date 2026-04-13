from django.core.management.base import BaseCommand

from intel.models import IntelIOC
from intel.services.scoring import apply_score_fields


class Command(BaseCommand):
    help = "Backfill calculated IOC scores for existing IntelIOC rows."

    def add_arguments(self, parser):
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            help="Rows per iterator batch (default: 500).",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Optional max rows to process (0 means no limit).",
        )
        parser.add_argument(
            "--only-missing",
            action="store_true",
            help="Only process rows where calculated_score is NULL.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Compute and report changes without writing updates.",
        )

    def handle(self, *args, **options):
        batch_size = max(int(options["batch_size"]), 1)
        limit = max(int(options["limit"]), 0)
        only_missing = bool(options["only_missing"])
        dry_run = bool(options["dry_run"])

        queryset = IntelIOC.objects.order_by("id")
        if only_missing:
            queryset = queryset.filter(calculated_score__isnull=True)
        if limit:
            queryset = queryset[:limit]

        processed = 0
        updated = 0

        for record in queryset.iterator(chunk_size=batch_size):
            processed += 1
            changed_fields = apply_score_fields(record)
            if not changed_fields:
                continue
            updated += 1
            if not dry_run:
                record.save(update_fields=changed_fields)

        mode = "DRY-RUN" if dry_run else "WRITE"
        self.stdout.write(
            f"[{mode}] processed={processed} updated={updated} unchanged={processed - updated}"
        )
