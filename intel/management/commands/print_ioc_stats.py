import json

from django.core.management.base import BaseCommand
from django.db.models import Count

from intel.models import IntelIOC


class Command(BaseCommand):
    """Print a compact health check for the IOC corpus."""

    help = "Print high-level IOC statistics from the local database."

    def handle(self, *args, **options):
        # Total row count is the quickest proof that imports are landing.
        total_records = IntelIOC.objects.count()

        # These grouped views show what kinds of indicators we actually have.
        by_source = list(
            IntelIOC.objects.values("source_name")
            .annotate(count=Count("id"))
            .order_by("-count", "source_name")
        )
        by_value_type = list(
            IntelIOC.objects.values("value_type")
            .annotate(count=Count("id"))
            .order_by("-count", "value_type")
        )
        top_malware_families = list(
            IntelIOC.objects.exclude(malware_family="")
            .values("malware_family")
            .annotate(count=Count("id"))
            .order_by("-count", "malware_family")[:10]
        )

        payload = {
            "total_records": total_records,
            "by_source": by_source,
            "by_value_type": by_value_type,
            "top_malware_families": top_malware_families,
        }

        self.stdout.write(json.dumps(payload, indent=2))
