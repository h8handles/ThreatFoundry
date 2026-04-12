from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import timezone as datetime_timezone
from hashlib import sha256
from typing import Callable

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from intel.models import IntelIOC


logger = logging.getLogger(__name__)


@dataclass
class IngestionResult:
    """Small summary returned after an import run."""

    created: int = 0
    updated: int = 0
    skipped: int = 0


Normalizer = Callable[[dict], dict | None]


def _parse_datetime(value: str | None):
    """Convert ThreatFox datetime strings into timezone-aware Python datetimes."""
    if not value:
        return None

    parsed = parse_datetime(value.replace(" ", "T"))
    if parsed is None:
        return None
    if timezone.is_naive(parsed):
        return timezone.make_aware(parsed, timezone=datetime_timezone.utc)
    return parsed


def _normalize_tags(tags):
    """Always store tags as a clean Python list."""
    if isinstance(tags, list):
        return [str(tag).strip() for tag in tags if str(tag).strip()]
    if isinstance(tags, str) and tags.strip():
        return [tags.strip()]
    return []


def _coerce_int(value):
    """Convert stringly-typed integer values into real ints when possible."""
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _first_nonempty(*values):
    """Return the first value that becomes non-empty once converted to text."""
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _stable_source_record_id(source_name: str, value_type: str, value: str) -> str:
    """Create a repeatable fallback key when the source does not expose one."""
    return sha256(f"{source_name}:{value_type}:{value}".encode()).hexdigest()


def _extract_pulses(record: dict) -> list[dict]:
    """Pull the OTX pulse list into one predictable shape."""
    pulse_info = record.get("pulse_info")
    if not isinstance(pulse_info, dict):
        return []

    pulses = pulse_info.get("pulses")
    if not isinstance(pulses, list):
        return []

    return [pulse for pulse in pulses if isinstance(pulse, dict)]


def _extract_reference_url(record: dict, pulses: list[dict]) -> str:
    """Use the first reference URL we can confidently find."""
    direct_reference = str(record.get("reference") or record.get("reference_url") or "").strip()
    if direct_reference:
        return direct_reference

    for pulse in pulses:
        references = pulse.get("references")
        if isinstance(references, list):
            for reference in references:
                text = str(reference or "").strip()
                if text:
                    return text

    return ""


def _merge_tags(*tag_sources) -> list[str]:
    """Flatten and deduplicate tags while preserving the original order."""
    seen: set[str] = set()
    merged: list[str] = []

    for tags in tag_sources:
        for tag in _normalize_tags(tags):
            if tag not in seen:
                seen.add(tag)
                merged.append(tag)

    return merged


def _reference_entries(provider: str, *urls) -> list[dict]:
    entries: list[dict] = []
    seen: set[str] = set()
    for url in urls:
        text = _first_nonempty(url)
        if not text or text in seen:
            continue
        seen.add(text)
        entries.append(
            {
                "provider": provider,
                "label": f"{provider.title()} reference",
                "url": text,
            }
        )
    return entries


def normalize_threatfox_record(record: dict) -> dict | None:
    """
    Translate one raw ThreatFox record into the project's internal IOC shape.

    This is the normalization step: source-specific field names are mapped to
    the simpler names we want to work with across the project.
    """
    if not isinstance(record, dict):
        return None

    value = str(record.get("ioc") or "").strip()
    value_type = str(record.get("ioc_type") or "").strip()

    if not value or not value_type:
        return None

    source_record_id = str(record.get("id") or "").strip()
    if not source_record_id:
        # If the feed ever omits its native ID, we still create a stable key.
        source_record_id = _stable_source_record_id("threatfox", value_type, value)

    malware_family = (
        str(record.get("malware_printable") or record.get("malware") or "").strip()
    )

    confidence_level = _coerce_int(record.get("confidence_level"))

    reference_url = str(record.get("reference") or "").strip()

    return {
        "source_name": "threatfox",
        "source_record_id": source_record_id,
        "value": value,
        "value_type": value_type,
        "threat_type": str(record.get("threat_type") or "").strip(),
        "malware_family": malware_family,
        "confidence_level": confidence_level,
        "first_seen": _parse_datetime(record.get("first_seen")),
        "last_seen": _parse_datetime(record.get("last_seen")),
        "reporter": str(record.get("reporter") or "").strip(),
        "reference_url": reference_url,
        "tags": _normalize_tags(record.get("tags")),
        "external_references": _reference_entries("threatfox", reference_url),
        "raw_payload": record,
    }


def normalize_alienvault_record(record: dict) -> dict | None:
    """
    Translate one AlienVault OTX record into the shared IOC shape.

    OTX records tend to be lighter than ThreatFox records, so we pick the
    reliable common fields and avoid inventing analyst-facing meaning where the
    source does not give us one directly.
    """
    if not isinstance(record, dict):
        return None

    value = _first_nonempty(
        record.get("indicator"),
        record.get("ioc"),
        record.get("value"),
    )
    value_type = _first_nonempty(
        record.get("type"),
        record.get("indicator_type"),
        record.get("ioc_type"),
    )

    if not value or not value_type:
        return None

    source_record_id = _first_nonempty(record.get("id"))
    if not source_record_id:
        source_record_id = _stable_source_record_id("alienvault", value_type, value)

    pulses = _extract_pulses(record)
    primary_pulse = pulses[0] if pulses else {}

    threat_type = _first_nonempty(
        record.get("threat_type"),
        record.get("role"),
        primary_pulse.get("name"),
    )
    malware_family = _first_nonempty(
        record.get("malware_family"),
        record.get("malware"),
    )
    confidence_level = _coerce_int(
        record.get("confidence") or record.get("confidence_level")
    )

    return {
        "source_name": "alienvault",
        "source_record_id": source_record_id,
        "value": value,
        "value_type": value_type,
        "threat_type": threat_type,
        "malware_family": malware_family,
        "confidence_level": confidence_level,
        "first_seen": _parse_datetime(
            record.get("created") or record.get("first_seen")
        ),
        "last_seen": _parse_datetime(
            record.get("modified") or record.get("updated") or record.get("last_seen")
        ),
        "reporter": _first_nonempty(
            record.get("author_name"),
            primary_pulse.get("author_name"),
            primary_pulse.get("author"),
        ),
        "reference_url": _extract_reference_url(record, pulses),
        "tags": _merge_tags(
            record.get("tags"),
            record.get("industries"),
            record.get("targeted_countries"),
            primary_pulse.get("tags"),
        ),
        "external_references": _reference_entries(
            "alienvault",
            _extract_reference_url(record, pulses),
            *(
                reference
                for pulse in pulses
                for reference in (pulse.get("references") or [])
            ),
        ),
        "raw_payload": record,
    }


def normalize_urlhaus_record(record: dict) -> dict | None:
    """
    Translate one URLHaus record into the shared IOC shape.

    We model the primary malicious URL as the IOC value and keep the rest of the
    URLHaus metadata in the raw payload for later pivots and enrichment.
    """
    if not isinstance(record, dict):
        return None

    value = _first_nonempty(record.get("url"))
    if not value:
        return None

    source_record_id = _first_nonempty(record.get("id"))
    if not source_record_id:
        source_record_id = _stable_source_record_id("urlhaus", "url", value)

    threat_type = _first_nonempty(
        record.get("threat"),
        record.get("url_status"),
    )
    malware_family = _first_nonempty(
        record.get("payloads")[0].get("signature")
        if isinstance(record.get("payloads"), list) and record.get("payloads")
        else "",
        record.get("signature"),
    )
    reference_url = _first_nonempty(
        record.get("urlhaus_reference"),
        record.get("reference_url"),
    )

    tags = _merge_tags(
        record.get("tags"),
        [record.get("url_status")],
        [record.get("threat")],
    )

    return {
        "source_name": "urlhaus",
        "source_record_id": source_record_id,
        "value": value,
        "value_type": "url",
        "threat_type": threat_type,
        "malware_family": malware_family,
        "confidence_level": None,
        "first_seen": _parse_datetime(record.get("date_added") or record.get("firstseen")),
        "last_seen": _parse_datetime(record.get("last_online") or record.get("lastseen")),
        "reporter": _first_nonempty(record.get("reporter")),
        "reference_url": reference_url,
        "tags": tags,
        "external_references": _reference_entries("urlhaus", reference_url),
        "raw_payload": record,
    }


def format_ioc_for_learning(record: IntelIOC) -> dict:
    """
    Return the compact IOC view we want to study and build on first.

    These names mirror the ThreatFox-style fields the project owner wants to
    reason about during the early learning phase.
    """
    # Use a type-specific field name in the CLI output so a domain prints as
    # `"domain": "example.com"` instead of the more abstract `"ioc": ...`.
    value_key_by_type = {
        "domain": "domain",
        "url": "url",
        "ip:port": "ip_port",
        "sha256_hash": "sha256_hash",
    }
    value_key = value_key_by_type.get(record.value_type, "ioc")

    payload = {
        "id": record.source_record_id,
        "threat_type": record.threat_type or None,
        "malware": record.malware_family or None,
        "confidence_level": record.confidence_level,
        "first_seen": record.first_seen.isoformat() if record.first_seen else None,
        "last_seen": record.last_seen.isoformat() if record.last_seen else None,
        "reporter": record.reporter or None,
        "tags": record.tags or None,
    }
    payload[value_key] = record.value
    return payload


def upsert_iocs(
    records: list[dict],
    normalizer: Normalizer = normalize_threatfox_record,
    *,
    dry_run: bool = False,
    provider_name: str | None = None,
) -> IngestionResult:
    """
    Insert new records and update existing ones in place.

    `source_name + source_record_id` is our deduplication key, which lets us run
    rolling imports without creating duplicate rows every time.
    """
    started_at = timezone.now()
    result = IngestionResult()

    try:
        for record in records:
            normalized = normalizer(record)
            if normalized is None:
                result.skipped += 1
                continue

            if dry_run:
                created = not IntelIOC.objects.filter(
                    source_name=normalized["source_name"],
                    source_record_id=normalized["source_record_id"],
                ).exists()
            else:
                with transaction.atomic():
                    _, created = IntelIOC.objects.update_or_create(
                        source_name=normalized["source_name"],
                        source_record_id=normalized["source_record_id"],
                        defaults=normalized,
                    )
            if created:
                result.created += 1
            else:
                result.updated += 1
    except Exception as exc:
        _log_ingestion_event(
            event="ingestion_upsert_failed",
            provider=provider_name or "",
            status="failure",
            started_at=started_at,
            records_fetched=len(records),
            records_created=result.created,
            records_updated=result.updated,
            records_skipped=result.skipped,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )
        raise

    status = "partial" if result.skipped else "success"
    _log_ingestion_event(
        event="ingestion_upsert_finished",
        provider=provider_name or "",
        status=status,
        started_at=started_at,
        records_fetched=len(records),
        records_created=result.created,
        records_updated=result.updated,
        records_skipped=result.skipped,
    )
    return result


def _log_ingestion_event(
    *,
    event: str,
    provider: str,
    status: str,
    started_at,
    records_fetched: int,
    records_created: int,
    records_updated: int,
    records_skipped: int,
    error_type: str = "",
    error_message: str = "",
) -> None:
    now = timezone.now()
    payload = {
        "event": event,
        "provider": provider,
        "status": status,
        "error_type": error_type,
        "error_message": error_message,
        "timestamp": now.isoformat(),
        "duration_seconds": (now - started_at).total_seconds(),
        "records_fetched": records_fetched,
        "records_created": records_created,
        "records_updated": records_updated,
        "records_skipped": records_skipped,
    }
    logger.info(json.dumps(payload, default=str, sort_keys=True))
