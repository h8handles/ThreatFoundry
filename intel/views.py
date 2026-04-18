import html
import json
import logging
from pathlib import Path
from html.parser import HTMLParser

import markdown
from django.conf import settings
from django.http import Http404, HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import Resolver404, resolve
from django.views.decorators.http import require_POST

from intel.access import VIEWER_GROUP, role_required
from intel.models import IntelIOC
from intel.services.correlation import build_hash_correlation_context
from intel.services.csv_export import iter_csv_lines
from intel.services.dashboard import (
    apply_dashboard_filters,
    apply_dashboard_sort,
    build_dashboard_context,
    build_detail_context,
    build_ioc_blade_detail_context,
    build_malware_directory_context,
    build_malware_family_context,
    parse_dashboard_filters,
    queryset_for_dashboard_filters,
)
from intel.services.reporting import generate_exec_report
from intel.time_display import TIME_DISPLAY_SESSION_KEY, get_time_display_definition
from intel.views_whois import lookup_whois_target

log = logging.getLogger(__name__)

WHOIS_SUPPORTED_VALUE_TYPES = {
    "domain",
    "host",
    "hostname",
    "fqdn",
    "ip",
    "ip_address",
    "ipv4",
    "ipv6",
}

DOCS_ALLOWED_TAGS = {
    "a",
    "blockquote",
    "code",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "li",
    "ol",
    "p",
    "pre",
    "strong",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
}
DOCS_ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "code": {"class"},
}
DOCS_ALLOWED_URL_SCHEMES = {"", "http", "https", "mailto"}


class DocumentationHtmlSanitizer(HTMLParser):
    """Allow Markdown-generated structure while keeping raw docs HTML inert."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag not in DOCS_ALLOWED_TAGS:
            return

        rendered_attrs = self._safe_attrs(tag, attrs)
        suffix = f" {rendered_attrs}" if rendered_attrs else ""
        self.parts.append(f"<{tag}{suffix}>")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in DOCS_ALLOWED_TAGS and tag != "hr":
            self.parts.append(f"</{tag}>")

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if tag not in DOCS_ALLOWED_TAGS:
            return
        rendered_attrs = self._safe_attrs(tag, attrs)
        suffix = f" {rendered_attrs}" if rendered_attrs else ""
        self.parts.append(f"<{tag}{suffix}>")

    def handle_data(self, data):
        self.parts.append(html.escape(data, quote=False))

    def handle_entityref(self, name):
        self.parts.append(html.escape(html.unescape(f"&{name};"), quote=False))

    def handle_charref(self, name):
        self.parts.append(html.escape(html.unescape(f"&#{name};"), quote=False))

    def get_html(self) -> str:
        return "".join(self.parts)

    def _safe_attrs(self, tag: str, attrs) -> str:
        allowed = DOCS_ALLOWED_ATTRIBUTES.get(tag, set())
        safe_attrs = []
        for name, value in attrs:
            attr_name = str(name or "").strip().lower()
            if attr_name not in allowed or value is None:
                continue
            attr_value = str(value)
            if attr_name == "href" and not _is_safe_docs_url(attr_value):
                continue
            safe_attrs.append(
                f'{attr_name}="{html.escape(attr_value, quote=True)}"'
            )
        return " ".join(safe_attrs)


def _is_safe_docs_url(value: str) -> bool:
    scheme = value.strip().split(":", 1)[0].lower() if ":" in value else ""
    return scheme in DOCS_ALLOWED_URL_SCHEMES


def render_safe_documentation_markdown(md_content: str) -> str:
    raw_html = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code"],
    )
    sanitizer = DocumentationHtmlSanitizer()
    sanitizer.feed(raw_html)
    sanitizer.close()
    return sanitizer.get_html()

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

    header = [
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

    def row_iterable():
        for record in ordered_queryset.iterator():
            tags = ", ".join(str(tag).strip() for tag in (record.tags or []) if str(tag).strip())
            yield [
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

    response = StreamingHttpResponse(iter_csv_lines(header, row_iterable()), content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="dashboard_scope_export.csv"'
    return response

@role_required(VIEWER_GROUP)
def ioc_detail_view(request, pk: int):
    record = get_object_or_404(IntelIOC, pk=pk)
    context = build_detail_context(record)
    context["hash_correlation"] = build_hash_correlation_context(record)
    context["raw_payload_pretty"] = json.dumps(record.raw_payload, indent=2, sort_keys=True)
    context["whois_blade"] = _build_whois_blade_context(record)
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
    """Render the in-app documentation wiki from repository markdown files.

    The docs area intentionally uses the existing `docs/*.md` files as the
    source of truth. New markdown files placed in that directory are discovered
    automatically, shown in the sidebar, and rendered through the same safe
    markdown path. The selected filename is validated against the discovered
    set before the file is read, which keeps the route from becoming a path
    traversal primitive.
    """

    docs_dir = (Path(settings.BASE_DIR) / "docs").resolve()
    if not docs_dir.exists() or not docs_dir.is_dir():
        raise Http404("Documentation directory not found.")

    docs_by_name = {
        doc_path.name: doc_path
        for doc_path in docs_dir.glob("*.md")
    }
    doc_files = sorted(
        docs_by_name,
        key=str.casefold,
    )
    if not doc_files:
        raise Http404("No documentation files found.")

    if doc_name is None:
        doc_name = doc_files[0]

    if doc_name not in doc_files:
        raise Http404("Documentation page not found.")

    doc_path = docs_by_name[doc_name].resolve()
    try:
        doc_path.relative_to(docs_dir)
    except ValueError as exc:
        log.warning("Rejected documentation path outside docs directory.")
        raise Http404("Documentation page not found.") from exc

    try:
        md_content = doc_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise Http404("Documentation page not found.") from exc
    except OSError as exc:
        log.exception("Documentation read failed.")
        raise Http404("Documentation page not found.") from exc

    html_content = render_safe_documentation_markdown(md_content)

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
    if redirect_to and redirect_to.startswith("/") and not redirect_to.startswith("//"):
        try:
            match = resolve(redirect_to.split("?", 1)[0].split("#", 1)[0])
        except Resolver404:
            match = None
        allowed_redirects = {
            "dashboard",
            "ioc_detail",
            "ioc_blade_detail",
            "malware_family",
            "documentation",
            "documentation_doc",
            "analyst_chat",
            "generate_exec_report",
        }
        if match and match.app_name == "intel" and match.url_name in allowed_redirects:
            return redirect(f"intel:{match.url_name}", *match.args, **match.kwargs)
    return redirect("intel:dashboard")

def _build_whois_blade_context(record: IntelIOC) -> dict:
    """Build the optional WHOIS/geolocation panel for IOC detail pages.

    This helper keeps lookup errors out of the template layer by returning a
    small status object for unsupported, failed, and successful lookups. The
    view can render the blade consistently while the enrichment service handles
    DNS safety checks, registrable-domain fallback, and provider exceptions.
    """
    value = (record.value or "").strip()
    value_type = (record.value_type or "").strip().lower().replace("-", "_")

    if not value or value_type not in WHOIS_SUPPORTED_VALUE_TYPES:
        return {
            "supported": False,
            "status": "unavailable",
            "status_label": "Unavailable",
            "message": "WHOIS/geolocation enrichment is available for IP and domain indicators.",
            "fields": [],
        }

    outcome = lookup_whois_target(value)
    if not outcome["ok"]:
        return {
            "supported": True,
            "status": "failed",
            "status_label": "Failed",
            "target": value,
            "message": outcome.get("error") or "Lookup failed.",
            "fields": [],
        }

    result = outcome.get("result") or {}
    whois = result.get("whois") or {}
    geolocation = result.get("geolocation") or {}

    summary_fields = [
        {"label": "Target", "value": result.get("target") or value},
        {"label": "WHOIS Lookup Target", "value": result.get("whois_lookup_target") or value},
        {"label": "Target Type", "value": result.get("target_type")},
        {"label": "Registered Domain", "value": result.get("registered_domain")},
        {"label": "Resolved IP", "value": result.get("resolved_ip")},
    ]
    whois_fields = [
        {"label": "Registrar", "value": whois.get("registrar")},
        {"label": "Organization", "value": whois.get("organization") or geolocation.get("organization")},
        {"label": "Creation Date", "value": whois.get("creation_date")},
        {"label": "Expiration Date", "value": whois.get("expiration_date")},
        {"label": "Updated Date", "value": whois.get("updated_date")},
    ]
    geolocation_fields = [
        {"label": "Country", "value": geolocation.get("country") or whois.get("country")},
        {"label": "City", "value": geolocation.get("city")},
        {"label": "Region", "value": geolocation.get("region")},
        {"label": "ISP", "value": geolocation.get("isp")},
        {"label": "ASN", "value": geolocation.get("asn")},
    ]

    return {
        "supported": True,
        "status": "ok",
        "status_label": "Ready",
        "target": value,
        "message": "",
        "fields": [
            {"heading": "Summary", "items": summary_fields},
            {"heading": "WHOIS", "items": whois_fields},
            {"heading": "Geolocation", "items": geolocation_fields},
        ],
    }

@role_required(VIEWER_GROUP)
def generate_exec_report_view(request):
    filters = parse_dashboard_filters(request.GET)
    context = build_dashboard_context(filters)

    kpis = context.get("kpis")
    ioc_blades = context.get("ioc_blades", [])
    recent_ioc_rows = context.get("recent_ioc_rows", [])

    report_data = generate_exec_report(
        kpis,
        ioc_blades,
        recent_ioc_rows,
        malware_distribution=context.get("malware_distribution"),
    )

    if request.GET.get("format") == "markdown":
        return HttpResponse(report_data["markdown"], content_type="text/markdown")
    return HttpResponse(report_data["html"], content_type="text/html; charset=utf-8")
