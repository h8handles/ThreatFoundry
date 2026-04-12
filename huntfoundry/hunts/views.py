from django.conf import settings
from django.http import Http404, StreamingHttpResponse

from intel.services.csv_export import iter_csv_lines


def export_hunt_results(request):
    if not getattr(settings, "ENABLE_EXPERIMENTAL_HUNTS", False):
        raise Http404("Hunt export is not available yet.")

    # Keep the import inside the function so incomplete hunts schema work does
    # not break module import if URLs are included accidentally.
    from .models import HuntResult

    header = ["ID", "Timestamp", "Description", "Severity", "Status"]

    def row_iterable():
        for result in HuntResult.objects.all().iterator():
            yield [result.id, result.timestamp, result.description, result.severity, result.status]

    response = StreamingHttpResponse(iter_csv_lines(header, row_iterable()), content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="hunt_results.csv"'
    return response
