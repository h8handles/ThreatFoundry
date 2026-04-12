import logging
import socket
import ssl
import datetime
import json
from typing import Dict, List, Optional

import whois
import dns.resolver
import tldextract
import requests

from django.utils import timezone

log = logging.getLogger(__name__)

WHOIS_TIMEOUT = 10
DNS_TIMEOUT = 5
SSL_TIMEOUT = 5
REQUEST_TIMEOUT = 10


def _safe_get(d: dict, key: str, default=None):
    try:
        return d.get(key, default)
    except Exception:
        return default


def _calculate_domain_age(creation_date: Optional[datetime.datetime]) -> Optional[int]:
    if not creation_date:
        return None
    delta = timezone.now() - creation_date
    return delta.days


def _extract_nameservers(whois_data: dict) -> List[str]:
    ns = whois_data.get("name_servers") or whois_data.get("nameServers") or whois_data.get("name_servers")
    if isinstance(ns, list):
        return [str(n).strip() for n in ns]
    if isinstance(ns, str):
        return [ns.strip()]
    return []


def _extract_status_values(whois_data: dict) -> List[str]:
    status = whois_data.get("status") or whois_data.get("statuses") or whois_data.get("status")
    if isinstance(status, list):
        return [str(s).strip() for s in status]
    if isinstance(status, str):
        return [status.strip()]
    return []


def _whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain, timeout=WHOIS_TIMEOUT)
        return w.__dict__ if hasattr(w, "__dict__") else {}
    except Exception as exc:
        log.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {}


def _dns_query(domain: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=DNS_TIMEOUT)
        return [str(r) for r in answers]
    except Exception as exc:
        log.debug("DNS %s query failed for %s: %s", record_type, domain, exc)
        return []


def _ssl_certificate(domain: str) -> Dict[str, Optional[str]]:
    try:
        cert_pem = ssl.get_server_certificate((domain, 443), timeout=SSL_TIMEOUT)
        cert_dict = ssl._ssl._test_decode_cert(cert_pem)
        issuer = _safe_get(cert_dict, "issuer", [])
        issuer_str = ", ".join([f"{k[0]}={k[1]}" for k in issuer]) if issuer else None
        subject = _safe_get(cert_dict, "subject", [])
        subject_str = ", ".join([f"{k[0]}={k[1]}" for k in subject]) if subject else None
        san = _safe_get(cert_dict, "subjectAltName", [])
        san_list = [s[1] for s in san if s[0] == "DNS"] if san else []
        valid_from = _safe_get(cert_dict, "notBefore")
        valid_to = _safe_get(cert_dict, "notAfter")
        sha256 = _safe_get(cert_dict, "sha256")
        return {
            "issuer": issuer_str,
            "subject": subject_str,
            "san": san_list,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "sha256": sha256,
        }
    except Exception as exc:
        log.debug("SSL certificate fetch failed for %s: %s", domain, exc)
        return {}


def _resolve_ips(domain: str) -> List[str]:
    return _dns_query(domain, "A") + _dns_query(domain, "AAAA")


def _extract_root_sub_tld(domain: str) -> Dict[str, str]:
    ext = tldextract.extract(domain)
    return {
        "root_domain": ext.registered_domain,
        "subdomain": ext.subdomain,
        "tld": ext.suffix,
    }


def enrich_domain(domain: str, timeout: int = 30) -> Dict:
    """
    Perform WHOIS, DNS, SSL, and reputation lookups for a domain.
    Returns a dictionary with all enrichment fields.
    """
    result: Dict = {
        "registrar": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "registrant_org": None,
        "nameservers": [],
        "status_values": [],
        "abuse_contact_email": None,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "cname": None,
        "cert_issuer": None,
        "cert_subject": None,
        "cert_san": [],
        "cert_valid_from": None,
        "cert_valid_to": None,
        "cert_sha256": None,
        "root_domain": None,
        "subdomain": None,
        "tld": None,
        "resolved_ips": [],
        "registrar_overlap": False,
        "nameserver_overlap": False,
        "domain_age_days": None,
        "reputation_sources": [],
    }

    # WHOIS
    whois_data = _whois_lookup(domain)
    result["registrar"] = _safe_get(whois_data, "registrar")
    result["creation_date"] = _safe_get(whois_data, "creation_date")
    result["updated_date"] = _safe_get(whois_data, "updated_date")
    result["expiration_date"] = _safe_get(whois_data, "expiration_date")
    result["registrant_org"] = _safe_get(whois_data, "org") or _safe_get(whois_data, "registrant")
    result["nameservers"] = _extract_nameservers(whois_data)
    result["status_values"] = _extract_status_values(whois_data)
    result["abuse_contact_email"] = _safe_get(whois_data, "abuse_contact")

    # DNS
    result["a_records"] = _dns_query(domain, "A")
    result["aaaa_records"] = _dns_query(domain, "AAAA")
    result["mx_records"] = _dns_query(domain, "MX")
    result["ns_records"] = _dns_query(domain, "NS")
    result["txt_records"] = _dns_query(domain, "TXT")
    result["cname"] = _dns_query(domain, "CNAME")[0] if _dns_query(domain, "CNAME") else None

    # SSL
    cert_info = _ssl_certificate(domain)
    result["cert_issuer"] = cert_info.get("issuer")
    result["cert_subject"] = cert_info.get("subject")
    result["cert_san"] = cert_info.get("san", [])
    result["cert_valid_from"] = cert_info.get("valid_from")
    result["cert_valid_to"] = cert_info.get("valid_to")
    result["cert_sha256"] = cert_info.get("sha256")

    # Domain parsing
    parsed = _extract_root_sub_tld(domain)
    result["root_domain"] = parsed["root_domain"]
    result["subdomain"] = parsed["subdomain"]
    result["tld"] = parsed["tld"]

    # Resolved IPs
    result["resolved_ips"] = _resolve_ips(domain)

    # Domain age
    if result["creation_date"]:
        try:
            if isinstance(result["creation_date"], list):
                # Some WHOIS clients return a list of dates
                creation = result["creation_date"][0]
            else:
                creation = result["creation_date"]
            if isinstance(creation, str):
                creation = datetime.datetime.strptime(creation, "%Y-%m-%d")
            result["domain_age_days"] = _calculate_domain_age(creation)
        except Exception as exc:
            log.debug("Failed to calculate domain age for %s: %s", domain, exc)

    # Reputation placeholders – real integration would populate these lists
    result["reputation_sources"] = []

    return result
