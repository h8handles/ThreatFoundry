"""Simple CLI entrypoint for WHOIS + geolocation enrichment lookups."""

import json
from datetime import datetime, timezone

from geo_client import lookup_ip_geolocation, resolve_domain_to_ip
from whois_client import lookup_domain_whois


def _normalize_domain(value: str | None) -> str | None:
    """Normalize domain-like values for consistent output."""
    if not value or not isinstance(value, str):
        return None
    return value.strip().lower()


def _extract_registered_domain(whois_data: dict) -> str | None:
    """Derive registered domain from WHOIS payload."""
    return _normalize_domain(whois_data.get("domain_name"))


def _has_enrichment_data(payload: dict) -> bool:
    """Return True when payload has meaningful enrichment data and no error."""
    if not isinstance(payload, dict) or "error" in payload:
        return False
    return any(value not in (None, "", [], {}) for value in payload.values())


def build_enrichment_result(queried_domain: str, domain_for_lookup: str) -> dict:
    """Run enrichment steps and return a combined structured payload."""
    whois_payload = {}
    geolocation_payload = {}
    resolved_ip = None

    try:
        whois_payload = lookup_domain_whois(domain_for_lookup)
        whois_payload["domain_name"] = _normalize_domain(whois_payload.get("domain_name"))
    except Exception as exc:
        whois_payload = {"error": str(exc)}

    try:
        resolved_ip = resolve_domain_to_ip(domain_for_lookup)
        geolocation_payload = {
            "resolved_ip": resolved_ip,
            **lookup_ip_geolocation(resolved_ip),
        }
    except Exception as exc:
        geolocation_payload = {"error": str(exc)}

    has_whois_data = _has_enrichment_data(whois_payload)
    has_geolocation = _has_enrichment_data(geolocation_payload)

    result = {
        "queried_domain": queried_domain,
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

    return result


def main() -> None:
    """Prompt for a domain, perform enrichment, and print JSON output."""
    queried_domain = input("Enter domain:")
    domain = queried_domain.strip()

    if not domain:
        print("Error: domain cannot be empty.")
        return

    result = build_enrichment_result(
        queried_domain=queried_domain,
        domain_for_lookup=domain.lower(),
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
