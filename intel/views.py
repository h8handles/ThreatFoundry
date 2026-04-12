import csv
import json
from pathlib import Path

from django.conf import settings
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from intel.access import VIEWER_GROUP, role_required
from intel.models import IntelIOC
from intel.services.correlation import build_hash_correlation_context
from intel.services.csv_export import sanitize_csv_row
from intel.services.dashboard import (
    apply_dashboard_filters,
    apply_dashboard_sort,
    build_ioc_blade_detail_context,
    build_dashboard_context,
    build_detail_context,
    build_malware_directory_context,
    build_malware_family_context,
    parse_dashboard_filters,
    queryset_for_dashboard_filters,
)
from intel.time_display import (
    TIME_DISPLAY_SESSION_KEY,
    get_time_display_definition,
)


@role_required(VIEWER_GROUP)
def dashboard_view(request):
    filters = parse_dashboard_filters(request.GET)
    context = build_dashboard_context(filters)
    return render(request, "intel/dashboard.html", context)


@role_required(VIEWER_GROUP)
def export_dashboard_csv_view(request):
    filters = parse_dashboard_filters(request.GET)
    filtered_queryset = apply_dashboard_filters(queryset_for_dashboard_filters(), filters)
    ordered_queryset = apply_dashboard_sort(filtered_queryset, filters)

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="dashboard_scope_export.csv"'
    writer = csv.writer(response)
    writer.writerow(
        [
            "id",
            "value",
            "value_type",
            "source_name",
            "source_record_id",
            "observed_at",
            "first_seen",
            "last_seen",
            "last_ingested_at",
            "threat_type",
            "malware_family",
            "effective_confidence_level",
            "confidence_level",
            "derived_confidence_level",
            "reporter",
            "reference_url",
            "tags",
        ]
    )

    for record in ordered_queryset.iterator():
        tags = ", ".join(str(tag).strip() for tag in (record.tags or []) if str(tag).strip())
        writer.writerow(
            sanitize_csv_row(
                [
                    record.id,
                    record.value,
                    record.value_type,
                    record.source_name,
                    record.source_record_id,
                    getattr(record, "timeline_at", None),
                    record.first_seen,
                    record.last_seen,
                    record.last_ingested_at,
                    getattr(record, "threat_bucket", "") or record.threat_type,
                    getattr(record, "malware_bucket", "") or record.malware_family,
                    getattr(record, "effective_confidence_level", ""),
                    record.confidence_level,
                    record.derived_confidence_level,
                    record.reporter,
                    record.reference_url,
                    tags,
                ]
            )
        )

    return response


@role_required(VIEWER_GROUP)
def ioc_detail_view(request, pk: int):
    record = get_object_or_404(IntelIOC, pk=pk)
    context = build_detail_context(record)
    context["hash_correlation"] = build_hash_correlation_context(record)
    context["raw_payload_pretty"] = json.dumps(record.raw_payload, indent=2, sort_keys=True)
    return render(request, "intel/ioc_detail.html", context)


@role_required(VIEWER_GROUP)
def ioc_blade_detail_view(request):
    value = (request.GET.get("value") or "").strip()
    value_type = (request.GET.get("value_type") or "").strip()
    if not value or not value_type:
        raise Http404("IOC blade not found.")

    context = build_ioc_blade_detail_context(value=value, value_type=value_type)
    if context is None:
        raise Http404("IOC blade not found.")

    return render(request, "intel/ioc_blade_detail.html", context)


@role_required(VIEWER_GROUP)
def malware_family_view(request):
    family = (request.GET.get("family") or "").strip()
    if not family:
        context = build_malware_directory_context()
        return render(request, "intel/malware_directory.html", context)

    try:
        page = int(request.GET.get("page") or 1)
    except (TypeError, ValueError):
        page = 1

    try:
        page_size = int(request.GET.get("page_size") or 20)
    except (TypeError, ValueError):
        page_size = 20

    context = build_malware_family_context(
        family=family,
        page=page,
        page_size=page_size,
    )
    return render(request, "intel/malware_family.html", context)


@role_required(VIEWER_GROUP)
def documentation_view(request, doc_name=None):
    import markdown

    docs_dir = Path(settings.BASE_DIR) / "docs"
    if not docs_dir.exists() or not docs_dir.is_dir():
        raise Http404("Documentation directory not found.")

    doc_files = sorted(
        [doc_path.name for doc_path in docs_dir.glob("*.md")],
        key=str.casefold,
    )
    if not doc_files:
        raise Http404("No documentation files found.")

    if doc_name is None:
        doc_name = doc_files[0]

    if doc_name not in doc_files:
        raise Http404("Documentation page not found.")

    doc_path = docs_dir / doc_name
    try:
        md_content = doc_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise Http404("Documentation page not found.") from exc

    html_content = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code"],
    )

    context = {
        "doc_files": doc_files,
        "current_doc": doc_name,
        "html_content": html_content,
    }
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return render(request, "intel/_documentation_content.html", context)

    return render(request, "intel/documentation.html", context)


@require_POST
@role_required(VIEWER_GROUP)
def set_time_display_view(request):
    selected = request.POST.get("time_display_option")
    request.session[TIME_DISPLAY_SESSION_KEY] = get_time_display_definition(selected).key

    redirect_to = request.POST.get("next")
    if redirect_to and url_has_allowed_host_and_scheme(
        url=redirect_to,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect(redirect_to)
    return redirect("intel:dashboard")
