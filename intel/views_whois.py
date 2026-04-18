import json
import logging
import time

from django.http import JsonResponse
from django.views.decorators.http import require_http_methods

from intel.access import VIEWER_GROUP, api_role_required
from intel.services.whois_enrichment import InvalidWhoisTargetError, enrich_target

log = logging.getLogger(__name__)

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = 20
_WHOIS_RATE_LIMIT: dict[str, list[float]] = {}


def _rate_limit_key(request) -> str:
    user_part = f"user:{request.user.pk}" if request.user.is_authenticated else "anon"
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    ip_part = forwarded_for.split(",", 1)[0].strip() or request.META.get("REMOTE_ADDR", "")
    return f"{user_part}:{ip_part}"


def _is_rate_limited(request, *, bucket: dict[str, list[float]], limit: int = _RATE_LIMIT_MAX_REQUESTS) -> bool:
    now = time.time()
    key = _rate_limit_key(request)
    bucket[key] = [ts for ts in bucket.get(key, []) if now - ts < _RATE_LIMIT_WINDOW_SECONDS]
    if len(bucket[key]) >= limit:
        return True
    bucket[key].append(now)
    return False


def lookup_whois_target(target):
    try:
        result = enrich_target(target)
    except InvalidWhoisTargetError as exc:
        log.warning("WHOIS lookup invalid target.")
        return {"ok": False, "error": "Invalid lookup target.", "status": 400}
    except Exception:
        log.exception("WHOIS lookup failed.")
        return {"ok": False, "error": "Lookup failed.", "status": 502}

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
    if _is_rate_limited(request, bucket=_WHOIS_RATE_LIMIT):
        return JsonResponse({"ok": False, "error": "Too many lookup requests."}, status=429)

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
