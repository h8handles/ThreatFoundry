from django.core.management.base import BaseCommand, CommandError

from intel.services.retention import trim_iocs_to_limit


class Command(BaseCommand):
    help = "Trim IOC rows to the newest N records using internal ingestion timestamps."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=1000,
            help="Number of newest IOC rows to keep (default: 1000).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be deleted without deleting rows.",
        )

    def handle(self, *args, **options):
        limit = options.get("limit", 1000)
        dry_run = options.get("dry_run", False)
        if limit is None or limit <= 0:
            raise CommandError("--limit must be greater than zero")

        result = trim_iocs_to_limit(limit=limit, dry_run=dry_run)

        self.stdout.write(f"status: {result.status}")
        self.stdout.write(f"message: {result.message}")
        self.stdout.write(f"limit: {result.limit}")
        self.stdout.write(f"dry_run: {result.dry_run}")
        self.stdout.write(f"before_count: {result.total_before}")
        self.stdout.write(f"deleted_count: {result.total_deleted}")
        self.stdout.write(f"retained_count: {result.total_retained}")
        self.stdout.write(f"after_count: {result.total_after}")

        if result.dashboard_snapshot is not None:
            self.stdout.write(
                "dashboard_snapshot: "
                f"result_count={result.dashboard_snapshot.get('result_count', 0)} "
                f"has_data={result.dashboard_snapshot.get('has_data', False)} "
                f"newest_ingest={result.dashboard_snapshot.get('newest_ingest', '')}"
            )

        if result.vacuum_recommended:
            self.stdout.write(
                "note: Large delete on PostgreSQL detected. "
                "Consider running VACUUM ANALYZE on the IOC table."
            )
