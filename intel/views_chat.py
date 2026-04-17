import json
import logging
import secrets

from django.http import JsonResponse
from django.shortcuts import render
from django.conf import settings
from django.views.decorators.http import require_POST

from intel.access import ANALYST_GROUP, api_role_required, role_required, user_has_minimum_role
from intel.services.chatbot import (
    ChatbotServiceError,
    SYSTEM_PROMPT,
    build_chat_bootstrap,
    build_chat_context,
    build_chat_response,
    build_scope_badges,
    resolve_summary_mode,
)
from intel.services.dashboard import parse_dashboard_filters

log = logging.getLogger(__name__)


@role_required(ANALYST_GROUP)
def analyst_chat_view(request):
    filters = parse_dashboard_filters(request.GET)
    context = {
        "chat_bootstrap": build_chat_bootstrap(filters),
        "scope_badges": build_scope_badges(filters),
    }
    return render(request, "intel/analyst_chat.html", context)


@require_POST
@api_role_required(ANALYST_GROUP)
def analyst_chat_api_view(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"ok": False, "error": "Invalid JSON payload."}, status=400)

    prompt = str(payload.get("prompt") or "").strip()
    if not prompt:
        return JsonResponse({"ok": False, "error": "Prompt is required."}, status=400)

    if len(prompt) > 2500:
        return JsonResponse(
            {"ok": False, "error": "Prompt is too long. Keep it under 2500 characters."},
            status=400,
        )

    try:
        response_payload = build_chat_response(
            user_prompt=prompt,
            summary_mode=payload.get("summary_mode"),
            filters_payload=payload.get("dashboard_filters"),
        )
    except ChatbotServiceError:
        log.exception("Analyst chat response generation failed")
        return JsonResponse({"ok": False, "error": "Assistant response generation failed."}, status=502)

    return JsonResponse({"ok": True, "response": response_payload})


def _has_context_api_access(request) -> bool:
    if request.user.is_authenticated and user_has_minimum_role(request.user, ANALYST_GROUP):
        return True

    configured_token = str(getattr(settings, "INTEL_CHAT_CONTEXT_API_TOKEN", "") or "").strip()
    if not configured_token:
        return False

    header_token = str(request.headers.get("X-ThreatFoundry-Service-Token") or "").strip()
    if not header_token:
        auth_header = str(request.headers.get("Authorization") or "").strip()
        if auth_header.lower().startswith("bearer "):
            header_token = auth_header[7:].strip()

    return bool(header_token) and secrets.compare_digest(header_token, configured_token)


@require_POST
def analyst_chat_context_api_view(request):
    if not _has_context_api_access(request):
        return JsonResponse(
            {
                "ok": False,
                "error": "Authentication required. Provide an analyst session or valid service token.",
            },
            status=401,
        )

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"ok": False, "error": "Invalid JSON payload."}, status=400)

    prompt = str(payload.get("prompt") or payload.get("user_query") or "").strip()
    if not prompt:
        return JsonResponse({"ok": False, "error": "Prompt is required."}, status=400)

    if len(prompt) > 2500:
        return JsonResponse(
            {"ok": False, "error": "Prompt is too long. Keep it under 2500 characters."},
            status=400,
        )

    filters = parse_dashboard_filters(payload.get("dashboard_filters") if isinstance(payload.get("dashboard_filters"), dict) else {})
    summary_mode = resolve_summary_mode(payload.get("summary_mode"), prompt)
    context = build_chat_context(filters, prompt)

    return JsonResponse(
        {
            "ok": True,
            "user_query": prompt,
            "summary_mode": summary_mode,
            "system_prompt": SYSTEM_PROMPT,
            "dashboard_filters": {
                "start_date": filters.start_date.isoformat() if filters.start_date else "",
                "end_date": filters.end_date.isoformat() if filters.end_date else "",
                "value_type": filters.value_type,
                "malware_family": filters.malware_family,
                "threat_type": filters.threat_type,
                "confidence_band": filters.confidence_band,
                "search": filters.search,
                "tag": filters.tag,
                "sort": filters.sort_by,
                "direction": filters.sort_direction,
                "page_size": filters.page_size,
            },
            "ioc_context": context,
        }
    )
