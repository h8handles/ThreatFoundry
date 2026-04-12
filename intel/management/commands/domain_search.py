import json

from django.core.management.base import BaseCommand, CommandError

from intel.models import IntelIOC
from intel.services.ingestion import format_ioc_for_learning


class Command(BaseCommand):
    """
    Search stored domain IOCs by partial or exact domain text.

    This keeps the search focused on domain indicators only, even though the
    database can also store URLs, IP:port values, and hashes.
    """

    help = "Search domain IOCs in the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "query",
            type=str,
            help="Full or partial domain to search for.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=10,
            help="Maximum number of matching domain IOCs to print.",
        )
        parser.add_argument(
            "--exact",
            action="store_true",
            help="Match the domain exactly instead of using partial matching.",
        )

    def handle(self, *args, **options):
        query = options["query"].strip()
        limit = options["limit"]
        exact = options["exact"]

        if not query:
            raise CommandError("Please provide a domain to search for.")
        if limit < 1:
            raise CommandError("--limit must be at least 1.")

        # Only search records that are actually stored as domains.
        records = IntelIOC.objects.filter(value_type="domain")

        if exact:
            records = records.filter(value__iexact=query)
        else:
            records = records.filter(value__icontains=query)

        records = records.order_by("-last_ingested_at", "-created_at", "value")[:limit]

        if not records:
            raise CommandError(f"No domain IOCs found matching '{query}'.")

        payload = [format_ioc_for_learning(record) for record in records]
        self.stdout.write(json.dumps(payload, indent=2))
        # print total count of matches at bottom of output
        self.stdout.write(f"\nTotal matches: {len(payload)}")
        




