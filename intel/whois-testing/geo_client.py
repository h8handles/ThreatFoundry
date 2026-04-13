"""Reusable geolocation enrichment client for domain lookups."""

from __future__ import annotations

import socket
from typing import Any

import requests

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_TIMEOUT_SECONDS = 8


def resolve_domain_to_ip(domain: str) -> str:
    """Resolve a domain name to an IPv4 address."""
    if not domain or "." not in domain:
        raise ValueError("Please provide a valid domain (example: example.com).")

    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for '{domain}'.") from exc


def lookup_ip_geolocation(ip_address: str) -> dict[str, Any]:
    """Look up geolocation details for an IP address using ip-api.com."""
    url = IP_API_URL.format(ip=ip_address)

    try:
        response = requests.get(url, timeout=IP_API_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError("Geolocation API request failed.") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("Geolocation API returned malformed JSON.") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("Geolocation API returned an unexpected response format.")

    if payload.get("status") != "success":
        message = payload.get("message", "unknown error")
        raise RuntimeError(f"Geolocation API lookup failed: {message}")

    return {
        "city": payload.get("city"),
        "region": payload.get("regionName"),
        "country": payload.get("country"),
        "latitude": payload.get("lat"),
        "longitude": payload.get("lon"),
        "isp": payload.get("isp"),
        "organization": payload.get("org"),
        "asn": payload.get("as"),
    }


def lookup_domain_geolocation(domain: str) -> dict[str, Any]:
    """Resolve a domain and return IP + geolocation enrichment data."""
    resolved_ip = resolve_domain_to_ip(domain)
    geo_data = lookup_ip_geolocation(resolved_ip)
    return {"resolved_ip": resolved_ip, **geo_data}
