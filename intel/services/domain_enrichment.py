import logging
import hashlib
import socket
import ssl
import datetime
from typing import Dict, List, Optional

try:
    import whois
except ImportError:  # pragma: no cover - depends on optional environment packages
    whois = None

try:
    import dns.resolver
except ImportError:  # pragma: no cover - depends on optional environment packages
    dns = None

try:
    import tldextract
except ImportError:  # pragma: no cover - depends on optional environment packages
    tldextract = None

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
    if isinstance(creation_date, datetime.date) and not isinstance(creation_date, datetime.datetime):
        creation_date = datetime.datetime.combine(creation_date, datetime.time.min)
    if timezone.is_naive(creation_date):
        creation_date = timezone.make_aware(creation_date, timezone.utc)
    delta = timezone.now() - creation_date
    return delta.days


def _extract_nameservers(whois_data: dict) -> List[str]:
    ns = whois_data.get("name_servers") or whois_data.get("nameServers")
    if isinstance(ns, list):
        return [str(n).strip() for n in ns]
    if isinstance(ns, str):
        return [ns.strip()]
    return []


def _extract_status_values(whois_data: dict) -> List[str]:
    status = whois_data.get("status") or whois_data.get("statuses")
    if isinstance(status, list):
        return [str(s).strip() for s in status]
    if isinstance(status, str):
        return [status.strip()]
    return []


def _whois_lookup(domain: str, timeout: int = WHOIS_TIMEOUT) -> dict:
    if whois is None:
        log.warning("python-whois is not installed; WHOIS lookup skipped for %s", domain)
        return {}
    try:
        w = whois.whois(domain, timeout=timeout)
        return w.__dict__ if hasattr(w, "__dict__") else {}
    except Exception as exc:
        log.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {}


def _dns_query(domain: str, record_type: str, timeout: int = DNS_TIMEOUT) -> List[str]:
    if dns is None:
        log.warning("dnspython is not installed; DNS lookup skipped for %s", domain)
        return []
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=timeout)
        return [str(r) for r in answers]
    except Exception as exc:
        log.debug("DNS %s query failed for %s: %s", record_type, domain, exc)
        return []


def _format_ssl_name(name_tuples) -> Optional[str]:
    if not name_tuples:
        return None

    flattened = []
    for rdn in name_tuples:
        for key, value in rdn:
            flattened.append(f"{key}={value}")
    return ", ".join(flattened) if flattened else None


def _ssl_certificate(domain: str, timeout: int = SSL_TIMEOUT) -> Dict[str, Optional[str]]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((domain, 443), timeout=timeout) as tcp_socket:
            with context.wrap_socket(tcp_socket, server_hostname=domain) as tls_socket:
                cert_dict = tls_socket.getpeercert() or {}
                cert_der = tls_socket.getpeercert(binary_form=True)

        issuer_str = _format_ssl_name(_safe_get(cert_dict, "issuer", []))
        subject_str = _format_ssl_name(_safe_get(cert_dict, "subject", []))
        san = _safe_get(cert_dict, "subjectAltName", [])
        san_list = [s[1] for s in san if s[0] == "DNS"] if san else []
        valid_from = _safe_get(cert_dict, "notBefore")
        valid_to = _safe_get(cert_dict, "notAfter")
        sha256 = hashlib.sha256(cert_der).hexdigest() if cert_der else None
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


def _extract_root_sub_tld(domain: str) -> Dict[str, str]:
    if tldextract is None:
        parts = (domain or "").strip(".").split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2])
            tld = parts[-1]
        else:
            root_domain = parts[0] if parts else ""
            subdomain = ""
            tld = ""
        return {
            "root_domain": root_domain,
            "subdomain": subdomain,
            "tld": tld,
        }

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
    whois_timeout = max(1, min(timeout, WHOIS_TIMEOUT))
    dns_timeout = max(1, min(timeout, DNS_TIMEOUT))
    ssl_timeout = max(1, min(timeout, SSL_TIMEOUT))

    whois_data = _whois_lookup(domain, timeout=whois_timeout)
    result["registrar"] = _safe_get(whois_data, "registrar")
    result["creation_date"] = _safe_get(whois_data, "creation_date")
    result["updated_date"] = _safe_get(whois_data, "updated_date")
    result["expiration_date"] = _safe_get(whois_data, "expiration_date")
    result["registrant_org"] = _safe_get(whois_data, "org") or _safe_get(whois_data, "registrant")
    result["nameservers"] = _extract_nameservers(whois_data)
    result["status_values"] = _extract_status_values(whois_data)
    result["abuse_contact_email"] = _safe_get(whois_data, "abuse_contact")

    # DNS
    dns_records = {
        "A": _dns_query(domain, "A", timeout=dns_timeout),
        "AAAA": _dns_query(domain, "AAAA", timeout=dns_timeout),
        "MX": _dns_query(domain, "MX", timeout=dns_timeout),
        "NS": _dns_query(domain, "NS", timeout=dns_timeout),
        "TXT": _dns_query(domain, "TXT", timeout=dns_timeout),
        "CNAME": _dns_query(domain, "CNAME", timeout=dns_timeout),
    }
    result["a_records"] = dns_records["A"]
    result["aaaa_records"] = dns_records["AAAA"]
    result["mx_records"] = dns_records["MX"]
    result["ns_records"] = dns_records["NS"]
    result["txt_records"] = dns_records["TXT"]
    result["cname"] = dns_records["CNAME"][0] if dns_records["CNAME"] else None

    # SSL
    cert_info = _ssl_certificate(domain, timeout=ssl_timeout)
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
    result["resolved_ips"] = result["a_records"] + result["aaaa_records"]

    # Domain age
    if result["creation_date"]:
        try:
            if isinstance(result["creation_date"], list):
                # Some WHOIS clients return a list of dates
                creation = result["creation_date"][0]
            else:
                creation = result["creation_date"]
            if isinstance(creation, str):
                try:
                    creation = datetime.datetime.fromisoformat(creation)
                except ValueError:
                    creation = datetime.datetime.strptime(creation, "%Y-%m-%d")
            result["domain_age_days"] = _calculate_domain_age(creation)
        except Exception as exc:
            log.debug("Failed to calculate domain age for %s: %s", domain, exc)

    # Reputation placeholders – real integration would populate these lists
    result["reputation_sources"] = []

    return result
