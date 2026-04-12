from django.urls import path
from .views import export_hunt_results

urlpatterns = [
    # other URLs...
    path('export-csv/', export_hunt_results, name='export-hunt-results'),
]
