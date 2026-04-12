from django.http import HttpResponse
import csv
from .models import HuntResult

def export_hunt_results(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="hunt_results.csv"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Timestamp', 'Description', 'Severity', 'Status'])

    results = HuntResult.objects.all()
    for result in results:
        writer.writerow([result.id, result.timestamp, result.description, result.severity, result.status])

    return response
