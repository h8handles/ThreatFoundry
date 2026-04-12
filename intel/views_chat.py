import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST

from intel.services.chatbot import (
    ChatbotServiceError,
    build_chat_bootstrap,
    build_chat_response,
    build_scope_badges,
)
from intel.services.dashboard import parse_dashboard_filters


def analyst_chat_view(request):
    filters = parse_dashboard_filters(request.GET)
    context = {
        "chat_bootstrap": build_chat_bootstrap(filters),
        "scope_badges": build_scope_badges(filters),
    }
    return render(request, "intel/analyst_chat.html", context)


@require_POST
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
    except ChatbotServiceError as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=502)

    return JsonResponse({"ok": True, "response": response_payload})
