"""Reusable geolocation enrichment client for domain lookups."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import requests

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_TIMEOUT_SECONDS = 8
DNS_TIMEOUT_SECONDS = 5


def is_safe_public_ip(ip_value: str) -> bool:
    """Return True only for routable public IP addresses."""
    try:
        ip = ipaddress.ip_address(str(ip_value or "").strip())
    except ValueError:
        return False

    return not any(
        (
            ip.is_loopback,
            ip.is_private,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        )
    )


def resolve_domain_ips(domain: str) -> list[str]:
    """Resolve all A/AAAA addresses for a domain and reject unsafe targets."""
    if not domain or "." not in domain:
        raise ValueError("Please provide a valid domain (example: example.com).")

    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT_SECONDS)
    try:
        addrinfo = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for '{domain}'.") from exc
    finally:
        socket.setdefaulttimeout(original_timeout)

    resolved_ips = sorted({item[4][0] for item in addrinfo if item and item[4]})
    if not resolved_ips:
        raise RuntimeError(f"DNS resolution returned no addresses for '{domain}'.")

    unsafe_ips = [ip for ip in resolved_ips if not is_safe_public_ip(ip)]
    if unsafe_ips:
        raise ValueError("Domain resolves to a blocked network range.")

    return resolved_ips


def resolve_domain_to_ip(domain: str) -> str:
    """Resolve a domain name to a safe public IP address."""
    return resolve_domain_ips(domain)[0]


def lookup_ip_geolocation(ip_address: str) -> dict[str, Any]:
    """Look up geolocation details for an IP address using ip-api.com."""
    if not is_safe_public_ip(ip_address):
        raise ValueError("IP address is in a blocked network range.")

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
        raise RuntimeError("Geolocation API lookup failed.")

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
