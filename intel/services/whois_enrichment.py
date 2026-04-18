from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from intel.services.whois_clients.geo_client import is_safe_public_ip, lookup_ip_geolocation, resolve_domain_to_ip
from intel.services.whois_clients.whois_client import lookup_domain_whois

try:
    import tldextract
except ImportError:  # pragma: no cover - depends on optional environment packages
    tldextract = None


log = logging.getLogger(__name__)

MAX_ENRICHMENT_RETRIES = 1
GENERIC_WHOIS_ERROR = "WHOIS lookup failed."
GENERIC_GEOLOCATION_ERROR = "Geolocation lookup failed."


class InvalidWhoisTargetError(ValueError):
    """Raised when the caller provides an invalid enrichment target."""


@dataclass(frozen=True)
class ParsedTarget:
    raw: str
    normalized: str
    target_type: str


def _normalize_domain(value: str | None) -> str | None:
    if not value or not isinstance(value, str):
        return None
    return value.strip().lower().rstrip(".")


def get_registrable_domain(domain: str) -> str:
    """Return registrable domain using PSL-aware parsing when available.

    Falls back to the original normalized value when parsing fails or when the
    input does not expose a registrable pair (for example: localhost).
    """
    normalized = _normalize_domain(domain) or str(domain or "").strip().lower()
    if not normalized:
        return normalized

    if tldextract is None:
        parts = normalized.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return normalized

    try:
        ext = tldextract.extract(normalized)
    except Exception:
        return normalized

    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return normalized


def _debug_domain_parts(domain: str) -> dict[str, str]:
    """Best-effort domain decomposition for diagnostics."""
    if tldextract is not None:
        ext = tldextract.extract(domain)
        return {
            "subdomain": ext.subdomain,
            "domain": ext.domain,
            "suffix": ext.suffix,
            "registered_domain": ext.registered_domain,
        }

    parts = (domain or "").split(".")
    return {
        "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else "",
        "domain": parts[-2] if len(parts) >= 2 else (parts[0] if parts else ""),
        "suffix": parts[-1] if parts else "",
        "registered_domain": ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else ""),
    }


def _extract_registered_domain(whois_data: dict[str, Any]) -> str | None:
    return _normalize_domain(str(whois_data.get("domain_name") or ""))


def _has_enrichment_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or "error" in payload:
        return False
    return any(value not in (None, "", [], {}) for value in payload.values())


def _normalize_whois_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize provider WHOIS shape before the UI consumes it."""
    payload["domain_name"] = _normalize_domain(str(payload.get("domain_name") or ""))
    return payload


def parse_target(value: str | None) -> ParsedTarget:
    """Validate and classify a user-provided WHOIS target.

    IP addresses are checked with the safe-public-IP guard before enrichment.
    Domain targets are normalized but are not DNS-resolved here so WHOIS can
    still fall back from noisy subdomains to their registrable domain.
    """
    raw = str(value or "").strip()
    log.debug("WHOIS parse_target received input.")
    if not raw:
        raise InvalidWhoisTargetError("Target is required.")

    try:
        normalized_ip = str(ipaddress.ip_address(raw))
        if not is_safe_public_ip(normalized_ip):
            raise InvalidWhoisTargetError("Target is not allowed.")
        return ParsedTarget(raw=raw, normalized=normalized_ip, target_type="ip")
    except InvalidWhoisTargetError:
        raise
    except ValueError:
        pass

    normalized_domain = _normalize_domain(raw)
    log.debug("WHOIS parse_target normalized domain.")
    if not normalized_domain or "." not in normalized_domain:
        raise InvalidWhoisTargetError("Please provide a valid domain or IP address.")
    if "://" in normalized_domain or "/" in normalized_domain:
        raise InvalidWhoisTargetError("Please provide only a domain or IP address, not a URL.")

    log.debug("WHOIS parse_target accepted domain target.")
    return ParsedTarget(raw=raw, normalized=normalized_domain, target_type="domain")


def _call_with_retries(operation, *args):
    for attempt in range(MAX_ENRICHMENT_RETRIES + 1):
        try:
            return operation(*args)
        except Exception as exc:
            if attempt >= MAX_ENRICHMENT_RETRIES:
                raise
            time.sleep(0.2)
    raise RuntimeError("Enrichment retry failed.")  # pragma: no cover


def _build_ip_result(target: ParsedTarget) -> dict[str, Any]:
    geolocation_payload: dict[str, Any] = {}
    try:
        geolocation_payload = {"resolved_ip": target.normalized, **_call_with_retries(lookup_ip_geolocation, target.normalized)}
    except Exception:
        log.exception("WHOIS IP geolocation failed.")
        geolocation_payload = {"error": GENERIC_GEOLOCATION_ERROR}

    has_geolocation = _has_enrichment_data(geolocation_payload)

    return {
        "target": target.raw,
        "target_type": target.target_type,
        "registered_domain": None,
        "resolved_ip": target.normalized,
        "summary": {
            "has_whois_data": False,
            "has_geolocation": has_geolocation,
            "resolution_success": True,
            "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "whois": {},
        "geolocation": geolocation_payload,
    }


def _build_domain_result(target: ParsedTarget) -> dict[str, Any]:
    """Build WHOIS and geolocation context for a domain target.

    WHOIS is attempted against the full normalized host first. When that fails
    for a subdomain, the code falls back to the registrable domain so analysts
    still get ownership context for infrastructure like random.host.example.
    DNS/IP safety remains in the geolocation path through `resolve_domain_to_ip`.
    """
    whois_payload: dict[str, Any] = {}
    geolocation_payload: dict[str, Any] = {}
    resolved_ip = None
    parts = _debug_domain_parts(target.normalized)
    registrable_domain = get_registrable_domain(target.normalized)
    whois_lookup_target = target.normalized
    log.debug(
        "WHOIS domain lookup start: raw=%r normalized=%r subdomain=%r domain=%r suffix=%r registered_domain=%r",
        target.raw,
        target.normalized,
        parts.get("subdomain"),
        parts.get("domain"),
        parts.get("suffix"),
        parts.get("registered_domain"),
    )
    log.info(
        "WHOIS lookup target resolved",
        extra={
            "raw_domain": target.normalized,
            "whois_target": whois_lookup_target,
            "registrable_domain": registrable_domain,
        },
    )

    try:
        if registrable_domain and registrable_domain != target.normalized:
            whois_payload = lookup_domain_whois(target.normalized)
        else:
            whois_payload = _call_with_retries(lookup_domain_whois, target.normalized)
        whois_payload = _normalize_whois_payload(whois_payload)
    except Exception as exc:
        log.warning(
            "WHOIS domain lookup failed: lookup_target=%r registered_domain_candidate=%r error=%s",
            target.normalized,
            parts.get("registered_domain"),
            exc,
        )
        if registrable_domain and registrable_domain != target.normalized:
            log.info(
                "WHOIS fallback activated",
                extra={
                    "raw_domain": target.normalized,
                    "fallback_target": registrable_domain,
                },
            )
            try:
                whois_payload = _call_with_retries(lookup_domain_whois, registrable_domain)
                whois_payload = _normalize_whois_payload(whois_payload)
                whois_lookup_target = registrable_domain
            except Exception as exc:
                log.warning(
                    "WHOIS fallback lookup failed: lookup_target=%r error=%s",
                    registrable_domain,
                    exc,
                )
                whois_payload = {"error": GENERIC_WHOIS_ERROR}
        else:
            whois_payload = {"error": GENERIC_WHOIS_ERROR}

    try:
        resolved_ip = resolve_domain_to_ip(target.normalized)
        geolocation_payload = {"resolved_ip": resolved_ip, **_call_with_retries(lookup_ip_geolocation, resolved_ip)}
    except Exception as exc:
        log.warning(
            "WHOIS geolocation lookup failed: lookup_target=%r error=%s",
            target.normalized,
            exc,
        )
        geolocation_payload = {"error": GENERIC_GEOLOCATION_ERROR}

    has_whois_data = _has_enrichment_data(whois_payload)
    has_geolocation = _has_enrichment_data(geolocation_payload)

    return {
        "target": target.raw,
        "whois_lookup_target": whois_lookup_target,
        "target_type": target.target_type,
        "registered_domain": _extract_registered_domain(whois_payload) if has_whois_data else None,
        "resolved_ip": resolved_ip,
        "summary": {
            "has_whois_data": has_whois_data,
            "has_geolocation": has_geolocation,
            "resolution_success": bool(resolved_ip),
            "enrichment_timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "whois": whois_payload,
        "geolocation": geolocation_payload,
    }


def enrich_target(value: str | None) -> dict[str, Any]:
    target = parse_target(value)
    if target.target_type == "ip":
        return _build_ip_result(target)
    return _build_domain_result(target)
