from django.core.management.base import BaseCommand

from intel.services.retention import cleanup_old_iocs


class Command(BaseCommand):
    help = (
        "Apply IOC retention policy: after 7+ days of data age, keep only the "
        "most recent 3 days of IOC records."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be deleted without deleting any rows.",
        )

    def handle(self, *args, **options):
        result = cleanup_old_iocs(dry_run=options.get("dry_run", False))

        self.stdout.write(f"status: {result.status}")
        self.stdout.write(f"message: {result.message}")
        self.stdout.write(f"cutoff_timestamp: {result.cutoff_timestamp}")
        self.stdout.write(f"oldest_timestamp: {result.oldest_timestamp}")
        self.stdout.write(f"total_rows_before: {result.total_before}")
        self.stdout.write(f"total_rows_deleted: {result.total_deleted}")
        self.stdout.write(f"total_rows_remaining: {result.total_remaining}")

