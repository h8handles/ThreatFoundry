from django.urls import path

from intel.views import (
    dashboard_view,
    documentation_view,
    export_dashboard_csv_view,
    generate_exec_report_view,
    ioc_blade_detail_view,
    ioc_detail_view,
    malware_family_view,
    set_time_display_view,
)
from intel.views_chat import (
    analyst_chat_api_view,
    analyst_chat_context_api_view,
    analyst_chat_view,
)
from intel.views_tickets import ticket_detail_view, ticket_list_view, ticket_note_create_view
from intel.views_whois import whois_lookup_api_view


app_name = "intel"

urlpatterns = [
    path("", dashboard_view, name="dashboard"),
    path("dashboard/", dashboard_view, name="dashboard_alias"),
    path("dashboard/export-csv/", export_dashboard_csv_view, name="dashboard_export_csv"),
    path("reports/executive/", generate_exec_report_view, name="generate_exec_report"),
    path("assistant/", analyst_chat_view, name="analyst_chat"),
    path("api/assistant/chat/", analyst_chat_api_view, name="analyst_chat_api"),
    path("api/assistant/context/", analyst_chat_context_api_view, name="analyst_chat_context_api"),
    path("tickets/", ticket_list_view, name="ticket_list"),
    path("tickets/<int:pk>/", ticket_detail_view, name="ticket_detail"),
    path("tickets/<int:pk>/notes/", ticket_note_create_view, name="ticket_note_create"),
    path("api/whois/", whois_lookup_api_view, name="whois_lookup_api"),
    path("docs/", documentation_view, name="documentation"),
    path("docs/<str:doc_name>/", documentation_view, name="documentation_doc"),
    path("malware/", malware_family_view, name="malware_family"),
    path("settings/time-display/", set_time_display_view, name="set_time_display"),
    path("ioc-blade/", ioc_blade_detail_view, name="ioc_blade_detail"),
    path("ioc/<int:pk>/", ioc_detail_view, name="ioc_detail"),
]
