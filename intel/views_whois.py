import json

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from intel.access import VIEWER_GROUP, api_role_required
from intel.services.whois_enrichment import InvalidWhoisTargetError, enrich_target


def lookup_whois_target(target):
    try:
        result = enrich_target(target)
    except InvalidWhoisTargetError as exc:
        return {"ok": False, "error": str(exc), "status": 400}
    except Exception as exc:
        return {"ok": False, "error": f"Lookup failed: {exc}", "status": 502}

    has_whois_data = bool(result.get("summary", {}).get("has_whois_data"))
    has_geolocation = bool(result.get("summary", {}).get("has_geolocation"))
    if not has_whois_data and not has_geolocation:
        return {
            "ok": False,
            "error": "Enrichment lookup failed.",
            "status": 502,
            "result": result,
        }

    return {"ok": True, "result": result, "status": 200}


@require_http_methods(["GET", "POST"])
@api_role_required(VIEWER_GROUP)
def whois_lookup_api_view(request):
    if request.method == "GET":
        target = request.GET.get("target") or request.GET.get("value")
    else:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return JsonResponse({"ok": False, "error": "Invalid JSON payload."}, status=400)
        target = payload.get("target") or payload.get("value")

    outcome = lookup_whois_target(target)
    response_payload = {"ok": outcome["ok"]}
    if outcome.get("error"):
        response_payload["error"] = outcome["error"]
    if outcome.get("result") is not None:
        response_payload["result"] = outcome["result"]
    return JsonResponse(response_payload, status=outcome["status"])
