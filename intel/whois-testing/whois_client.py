"""Reusable WHOIS client utilities for enrichment workflows."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

import whois


def _to_iso(value: Any) -> Any:
    """Convert datetime/date values (or lists of them) into ISO strings."""
    if isinstance(value, list):
        return [_to_iso(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _first_or_value(value: Any) -> Any:
    """Normalize list-style fields to their first item for consistent output."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _as_list(value: Any) -> list[Any]:
    """Normalize scalar/list values to list form for multi-value fields."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def lookup_domain_whois(domain: str) -> dict[str, Any]:
    """
    Perform WHOIS lookup and return normalized structured data.

    Expected output keys:
    - domain_name
    - registrar
    - creation_date
    - expiration_date
    - updated_date
    - name_servers
    - status
    - emails
    - organization
    - country
    """
    if not domain or "." not in domain:
        raise ValueError("Please provide a valid domain (example: example.com).")

    raw = whois.whois(domain)

    # python-whois returns either dict-like objects or custom objects
    # with attributes depending on TLD/response format.
    get = raw.get if hasattr(raw, "get") else lambda key: getattr(raw, key, None)

    result = {
        "domain_name": _to_iso(_first_or_value(get("domain_name"))),
        "registrar": _to_iso(_first_or_value(get("registrar"))),
        "creation_date": _to_iso(_first_or_value(get("creation_date"))),
        "expiration_date": _to_iso(_first_or_value(get("expiration_date"))),
        "updated_date": _to_iso(_first_or_value(get("updated_date"))),
        "name_servers": _to_iso(_as_list(get("name_servers"))),
        "status": _to_iso(_as_list(get("status"))),
        "emails": _to_iso(_as_list(get("emails"))),
        "organization": _to_iso(_first_or_value(get("org"))),
        "country": _to_iso(_first_or_value(get("country"))),
    }

    # Provide a fallback if organization field name varies by registrar response.
    if not result["organization"]:
        result["organization"] = _to_iso(_first_or_value(get("registrant_organization")))

    return result
