from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from datetime import datetime, timezone as datetime_timezone
from time import sleep
from urllib.parse import quote

import requests
from django.utils import timezone

try:
    from intel.services.env import load_project_env
except ModuleNotFoundError:  # Running this file directly keeps imports local.
    from env import load_project_env
from intel.services.common import (
    coerce_int as _coerce_int,
    first_nonempty_text as _first_nonempty_text,
)
from intel.services.provider_registry import build_provider_links
from intel.services.scoring import apply_score_fields

load_project_env()


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


class UnsupportedVirusTotalLookup(RuntimeError):
    """Raised when a local IOC type cannot be translated to a VT lookup."""


class VirusTotalNotFound(RuntimeError):
    """Raised when VirusTotal has no report for the requested indicator."""


@dataclass(frozen=True)
class VirusTotalLookup:
    object_path: str
    object_type: str
    lookup_value: str
    display_value: str
    platform_type: str


def get_virustotal_api_key() -> str | None:
    """Read the VirusTotal API key from the environment."""
    return os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")


def build_lookup(value: str, value_type: str) -> VirusTotalLookup:
    """Map the platform IOC type into the correct VirusTotal object endpoint."""
    text_value = str(value or "").strip()
    normalized_type = str(value_type or "").strip().lower()

    if not text_value or not normalized_type:
        raise UnsupportedVirusTotalLookup("VirusTotal lookup requires both value and type.")

    if normalized_type in {"md5_hash", "sha1_hash", "sha256_hash"}:
        return VirusTotalLookup(
            object_path=f"/files/{quote(text_value)}",
            object_type="file",
            lookup_value=text_value,
            display_value=text_value,
            platform_type=normalized_type,
        )

    if normalized_type in {"filehash-md5", "filehash-sha1", "filehash-sha256"}:
        return VirusTotalLookup(
            object_path=f"/files/{quote(text_value)}",
            object_type="file",
            lookup_value=text_value,
            display_value=text_value,
            platform_type=normalized_type,
        )

    if normalized_type in {"domain", "hostname"}:
        return VirusTotalLookup(
            object_path=f"/domains/{quote(text_value.lower())}",
            object_type="domain",
            lookup_value=text_value.lower(),
            display_value=text_value,
            platform_type=normalized_type,
        )

    if normalized_type in {"ip", "ipv4", "ipv6"}:
        return VirusTotalLookup(
            object_path=f"/ip_addresses/{quote(text_value)}",
            object_type="ip_address",
            lookup_value=text_value,
            display_value=text_value,
            platform_type=normalized_type,
        )

    if normalized_type == "ip:port":
        ip_value = text_value.rsplit(":", 1)[0].strip()
        if not ip_value:
            raise UnsupportedVirusTotalLookup(
                f"Could not extract an IP address from {text_value!r}."
            )
        return VirusTotalLookup(
            object_path=f"/ip_addresses/{quote(ip_value)}",
            object_type="ip_address",
            lookup_value=ip_value,
            display_value=text_value,
            platform_type=normalized_type,
        )

    if normalized_type == "url":
        return VirusTotalLookup(
            object_path=f"/urls/{_build_url_identifier(text_value)}",
            object_type="url",
            lookup_value=text_value,
            display_value=text_value,
            platform_type=normalized_type,
        )

    raise UnsupportedVirusTotalLookup(
        f"VirusTotal lookup is not supported for IOC type {value_type!r}."
    )


def fetch_virustotal_report(value: str, value_type: str, timeout: int = 30) -> dict:
    """
    Fetch a VirusTotal report for a supported IOC.

    The response is returned in raw JSON form so normalization can stay separate
    from the HTTP request step.
    """
    api_key = get_virustotal_api_key()
    if not api_key:
        raise RuntimeError(
            "VirusTotal API key not found. Set VIRUSTOTAL_API_KEY in your environment."
        )

    lookup = build_lookup(value, value_type)
    response = requests.get(
        f"{VIRUSTOTAL_API_URL}{lookup.object_path}",
        headers={"x-apikey": api_key},
        timeout=timeout,
    )

    if response.status_code == 404:
        raise VirusTotalNotFound(
            f"VirusTotal has no {lookup.object_type} report for {lookup.lookup_value}."
        )

    response.raise_for_status()
    return response.json()


def build_virustotal_enrichment(value: str, value_type: str, payload: dict) -> dict:
    """Translate a raw VT response into the additive enrichment shape we store."""
    lookup = build_lookup(value, value_type)
    data = payload.get("data") if isinstance(payload, dict) else {}
    if not isinstance(data, dict):
        data = {}

    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        attributes = {}

    stats = _as_dict(attributes.get("last_analysis_stats"))
    classification = _as_dict(attributes.get("popular_threat_classification"))
    tags = _normalize_list(attributes.get("tags"))
    categories = _normalize_mapping_values(attributes.get("categories"))
    sandbox_summary = _extract_sandbox_summary(attributes.get("sandbox_verdicts"))
    popular_names = _extract_ranked_labels(classification.get("popular_threat_name"))
    popular_categories = _extract_ranked_labels(
        classification.get("popular_threat_category")
    )

    reference_url = _first_nonempty_text(
        _as_dict(data.get("links")).get("self"),
        _as_dict(payload.get("links")).get("self") if isinstance(payload, dict) else "",
    )

    summary = {
        "object_id": str(data.get("id") or "").strip(),
        "object_type": _first_nonempty_text(data.get("type"), lookup.object_type),
        "lookup_type": lookup.object_type,
        "lookup_value": lookup.lookup_value,
        "platform_type": lookup.platform_type,
        "reference_url": reference_url,
        "title": _first_nonempty_text(attributes.get("title")),
        "meaningful_name": _first_nonempty_text(attributes.get("meaningful_name")),
        "names": _normalize_list(attributes.get("names")),
        "type_description": _first_nonempty_text(attributes.get("type_description")),
        "type_tag": _first_nonempty_text(attributes.get("type_tag")),
        "size": _coerce_int(attributes.get("size")),
        "reputation": _coerce_int(attributes.get("reputation")),
        "analysis_stats": stats,
        "analysis_score": _derive_confidence_score(stats),
        "detection_ratio": _build_detection_ratio(stats),
        "malicious_count": _coerce_int(stats.get("malicious")),
        "suspicious_count": _coerce_int(stats.get("suspicious")),
        "harmless_count": _coerce_int(stats.get("harmless")),
        "undetected_count": _coerce_int(stats.get("undetected")),
        "timeout_count": _coerce_int(stats.get("timeout")),
        "last_analysis_date": _timestamp_to_iso(attributes.get("last_analysis_date")),
        "first_submission_date": _timestamp_to_iso(
            attributes.get("first_submission_date")
        ),
        "last_submission_date": _timestamp_to_iso(attributes.get("last_submission_date")),
        "tags": tags,
        "category_labels": categories,
        "popular_threat_label": _first_nonempty_text(
            classification.get("suggested_threat_label")
        ),
        "popular_threat_names": popular_names,
        "popular_threat_categories": popular_categories,
        "sandbox_malware_names": sandbox_summary["malware_names"],
        "sandbox_categories": sandbox_summary["categories"],
        "sandbox_highest_confidence": sandbox_summary["highest_confidence"],
        "md5": _first_nonempty_text(attributes.get("md5")),
        "sha1": _first_nonempty_text(attributes.get("sha1")),
        "sha256": _first_nonempty_text(attributes.get("sha256")),
        "url": _first_nonempty_text(attributes.get("url")),
        "last_final_url": _first_nonempty_text(attributes.get("last_final_url")),
        "country": _first_nonempty_text(attributes.get("country")),
        "network": _first_nonempty_text(attributes.get("network")),
        "as_owner": _first_nonempty_text(attributes.get("as_owner")),
        "jarm": _first_nonempty_text(attributes.get("jarm")),
        "whois": _first_nonempty_text(attributes.get("whois")),
    }

    return {
        "provider": "virustotal",
        "fetched_at": timezone.now().isoformat(),
        "lookup": {
            "object_type": lookup.object_type,
            "platform_type": lookup.platform_type,
            "lookup_value": lookup.lookup_value,
            "display_value": lookup.display_value,
        },
        "summary": summary,
        "raw": payload,
    }


def derive_platform_updates(enrichment: dict) -> dict:
    """Pick the small set of VT fields that can improve the shared platform view."""
    summary = _as_dict(enrichment.get("summary"))
    family = _first_nonempty_text(
        _first_label(summary.get("popular_threat_names")),
        _first_label(summary.get("sandbox_malware_names")),
    )
    threat_type = _first_nonempty_text(
        _first_label(summary.get("popular_threat_categories")),
        _first_label(summary.get("sandbox_categories")),
        _first_nonempty_text(summary.get("popular_threat_label")).split(".", 1)[0],
    )
    reference_url = _first_nonempty_text(summary.get("reference_url"))

    return {
        "malware_family": family,
        "threat_type": threat_type,
        "confidence_level": _coerce_int(summary.get("analysis_score")),
        "reference_url": reference_url,
        "tags": _normalize_list(summary.get("tags")),
    }


def enrich_ioc_record(record, force: bool = False, timeout: int = 30) -> bool:
    """
    Fetch VirusTotal context for one IOC and merge it into the local record.

    Returns True when the record changed and False when it was already enriched
    and `force` was not requested.
    """
    enrichment_payloads = dict(record.enrichment_payloads or {})
    if not force and "virustotal" in enrichment_payloads:
        return False

    now = timezone.now()
    payload = fetch_virustotal_report(record.value, record.value_type, timeout=timeout)
    enrichment = build_virustotal_enrichment(record.value, record.value_type, payload)
    enrichment_payloads["virustotal"] = enrichment

    update_fields = [
        "enrichment_payloads",
        "external_references",
        "last_enriched_at",
        "last_enrichment_providers",
        "updated_at",
    ]
    record.enrichment_payloads = enrichment_payloads
    record.last_enriched_at = now
    record.last_enrichment_providers = _merge_tags(
        record.last_enrichment_providers,
        ["virustotal"],
    )

    gui_links = build_provider_links(
        "virustotal",
        value=record.value,
        value_type=record.value_type,
        enrichment_summary=enrichment.get("summary") or {},
    )
    merged_references = _merge_reference_entries(
        record.external_references,
        gui_links,
    )
    if merged_references != _normalize_reference_entries(record.external_references):
        record.external_references = merged_references

    derived = derive_platform_updates(enrichment)
    if not _first_nonempty_text(record.malware_family) and derived["malware_family"]:
        record.malware_family = derived["malware_family"]
        update_fields.append("malware_family")
    if not _first_nonempty_text(record.threat_type) and derived["threat_type"]:
        record.threat_type = derived["threat_type"]
        update_fields.append("threat_type")
    if record.confidence_level is None and derived["confidence_level"] is not None:
        record.confidence_level = derived["confidence_level"]
        update_fields.append("confidence_level")
    if not _first_nonempty_text(record.reference_url) and derived["reference_url"]:
        record.reference_url = derived["reference_url"]
        update_fields.append("reference_url")

    merged_tags = _merge_tags(record.tags, derived["tags"])
    if merged_tags != _normalize_list(record.tags):
        record.tags = merged_tags
        update_fields.append("tags")

    update_fields.extend(apply_score_fields(record))
    record.save(update_fields=list(dict.fromkeys(update_fields)))
    return True


def throttle_request(delay_seconds: float):
    """Small wrapper so the command can respect public API quotas and stay testable."""
    if delay_seconds > 0:
        sleep(delay_seconds)


def _build_url_identifier(value: str) -> str:
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _extract_sandbox_summary(value) -> dict:
    if not isinstance(value, dict):
        return {"malware_names": [], "categories": [], "highest_confidence": None}

    malware_names: list[str] = []
    categories: list[str] = []
    highest_confidence = None

    for sandbox in value.values():
        if not isinstance(sandbox, dict):
            continue

        malware_names = _merge_tags(malware_names, sandbox.get("malware_names"))
        categories = _merge_tags(
            categories,
            sandbox.get("malware_classification"),
            sandbox.get("category"),
        )

        confidence = _coerce_int(sandbox.get("confidence"))
        if confidence is not None and (
            highest_confidence is None or confidence > highest_confidence
        ):
            highest_confidence = confidence

    return {
        "malware_names": malware_names,
        "categories": categories,
        "highest_confidence": highest_confidence,
    }


def _derive_confidence_score(stats: dict) -> int | None:
    malicious = _coerce_int(stats.get("malicious")) or 0
    suspicious = _coerce_int(stats.get("suspicious")) or 0
    numeric_values = [
        value
        for value in (_coerce_int(item) for item in stats.values())
        if value is not None and value >= 0
    ]
    total = sum(numeric_values)
    if total <= 0:
        return None

    weighted_hits = malicious + (suspicious * 0.5)
    score = round((weighted_hits / total) * 100)
    return max(0, min(100, score))


def _build_detection_ratio(stats: dict) -> str:
    malicious = _coerce_int(stats.get("malicious")) or 0
    suspicious = _coerce_int(stats.get("suspicious")) or 0
    numeric_values = [
        value
        for value in (_coerce_int(item) for item in stats.values())
        if value is not None and value >= 0
    ]
    total = sum(numeric_values)
    if total <= 0:
        return ""
    return f"{malicious + suspicious}/{total}"


def _timestamp_to_iso(value) -> str:
    if value in (None, ""):
        return ""

    timestamp = _coerce_int(value)
    if timestamp is None:
        return ""

    return datetime.fromtimestamp(timestamp, tz=datetime_timezone.utc).isoformat()


def _extract_ranked_labels(value) -> list[dict]:
    if not isinstance(value, list):
        return []

    labels = []
    for item in value:
        if not isinstance(item, dict):
            continue
        label = _first_nonempty_text(item.get("value"))
        count = _coerce_int(item.get("count"))
        if label:
            labels.append({"label": label, "count": count})
    return labels


def _normalize_mapping_values(value) -> list[str]:
    if not isinstance(value, dict):
        return []

    normalized = []
    seen: set[str] = set()
    for item in value.values():
        label = _first_nonempty_text(item)
        if label and label not in seen:
            seen.add(label)
            normalized.append(label)
    return normalized


def _merge_tags(*sources) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()

    for source in sources:
        for tag in _normalize_list(source):
            if tag not in seen:
                seen.add(tag)
                merged.append(tag)

    return merged


def _normalize_reference_entries(value) -> list[dict]:
    if not isinstance(value, list):
        return []

    normalized: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        url = _first_nonempty_text(item.get("url"))
        if not url:
            continue
        normalized.append(
            {
                "provider": _first_nonempty_text(item.get("provider")),
                "label": _first_nonempty_text(item.get("label")) or "External reference",
                "url": url,
                "note": _first_nonempty_text(item.get("note")),
            }
        )
    return normalized


def _merge_reference_entries(*sources) -> list[dict]:
    merged: list[dict] = []
    seen: set[str] = set()

    for source in sources:
        for item in _normalize_reference_entries(source):
            if item["url"] in seen:
                continue
            seen.add(item["url"])
            merged.append(item)

    return merged


def _normalize_list(value) -> list[str]:
    if isinstance(value, str):
        value = [value]

    if not isinstance(value, list):
        return []

    normalized = []
    for item in value:
        text = _first_nonempty_text(item)
        if text:
            normalized.append(text)
    return normalized


def _first_label(items) -> str:
    if isinstance(items, list) and items:
        first = items[0]
        if isinstance(first, dict):
            return _first_nonempty_text(first.get("label"))
        return _first_nonempty_text(first)
    return ""


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}
