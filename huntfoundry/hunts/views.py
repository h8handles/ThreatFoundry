import csv

from django.conf import settings
from django.http import Http404, HttpResponse

from intel.services.csv_export import sanitize_csv_row


def export_hunt_results(request):
    if not getattr(settings, "ENABLE_EXPERIMENTAL_HUNTS", False):
        raise Http404("Hunt export is not available yet.")

    # Keep the import inside the function so incomplete hunts schema work does
    # not break module import if URLs are included accidentally.
    from .models import HuntResult

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="hunt_results.csv"'

    writer = csv.writer(response)
    writer.writerow(["ID", "Timestamp", "Description", "Severity", "Status"])

    for result in HuntResult.objects.all():
        writer.writerow(
            sanitize_csv_row(
                [result.id, result.timestamp, result.description, result.severity, result.status]
            )
        )

    return response
