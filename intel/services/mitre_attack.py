from __future__ import annotations

import requests

from intel.services.ingestion import _first_nonempty, _merge_tags, _parse_datetime, _reference_entries


MITRE_ATTACK_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def fetch_mitre_attack_enterprise(timeout: int = 30) -> dict:
    response = requests.get(MITRE_ATTACK_ENTERPRISE_URL, timeout=timeout)
    response.raise_for_status()
    return response.json()


def extract_attack_patterns(payload: dict) -> list[dict]:
    objects = payload.get("objects") if isinstance(payload, dict) else None
    if not isinstance(objects, list):
        return []
    return [
        item
        for item in objects
        if isinstance(item, dict)
        and item.get("type") == "attack-pattern"
        and not item.get("revoked")
        and not item.get("x_mitre_deprecated")
    ]


def normalize_attack_pattern(record: dict) -> dict | None:
    if not isinstance(record, dict):
        return None

    external_id, reference_url = _attack_external_reference(record)
    name = _first_nonempty(record.get("name"))
    if not external_id or not name:
        return None

    tactics = [
        _first_nonempty(phase.get("phase_name")).replace("-", " ")
        for phase in record.get("kill_chain_phases") or []
        if isinstance(phase, dict) and _first_nonempty(phase.get("phase_name"))
    ]
    created = _parse_datetime(record.get("created"))
    modified = _parse_datetime(record.get("modified"))

    return {
        "source_name": "mitre_attack",
        "source_record_id": external_id,
        "value": f"{external_id} {name}",
        "value_type": "attack_technique",
        "threat_type": ", ".join(tactics[:3]) if tactics else "attack technique",
        "malware_family": "",
        "confidence_level": None,
        "first_seen": created,
        "last_seen": modified or created,
        "reporter": "MITRE ATT&CK",
        "reference_url": reference_url,
        "tags": _merge_tags(["mitre-attack", "attack-technique"], tactics),
        "external_references": _reference_entries("mitre_attack", reference_url),
        "raw_payload": record,
    }


def _attack_external_reference(record: dict) -> tuple[str, str]:
    for reference in record.get("external_references") or []:
        if not isinstance(reference, dict):
            continue
        source_name = _first_nonempty(reference.get("source_name")).lower()
        external_id = _first_nonempty(reference.get("external_id"))
        url = _first_nonempty(reference.get("url"))
        if source_name == "mitre-attack" and external_id:
            return external_id, url
    return "", ""
