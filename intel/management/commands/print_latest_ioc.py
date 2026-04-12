import json

from django.core.management.base import BaseCommand, CommandError

from intel.models import IntelIOC
from intel.services.ingestion import format_ioc_for_learning


class Command(BaseCommand):
    """
    Print the newest IOC using the compact field set we care about first.

    The goal is to make the CLI output easy to compare with ThreatFox records
    while we learn the data and shape the project.
    """

    help = "Print the most recently ingested IOC using the learning field set."

    def handle(self, *args, **options):
        # Order by ingestion time so the command shows the latest saved record.
        record = (
            IntelIOC.objects.order_by("-last_ingested_at", "-created_at", "-id").first()
        )
        if record is None:
            raise CommandError("No IOC records found.")

        payload = format_ioc_for_learning(record)

        self.stdout.write(json.dumps(payload, indent=2))
