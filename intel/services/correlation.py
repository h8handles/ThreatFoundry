from __future__ import annotations

from collections import Counter

from intel.models import IntelIOC


HASH_TYPE_ALIASES = {
    "md5": {"FileHash-MD5", "md5_hash"},
    "sha1": {"FileHash-SHA1", "sha1_hash"},
    "sha256": {"FileHash-SHA256", "sha256_hash"},
}


def canonical_hash_type(value_type: str | None) -> str | None:
    text = str(value_type or "").strip()
    for canonical, aliases in HASH_TYPE_ALIASES.items():
        if text in aliases:
            return canonical
    return None


def build_hash_correlation_context(record: IntelIOC, limit: int = 10) -> dict:
    """
    Correlate a hash IOC against ThreatFox and summarize any malware-family hits.

    We only perform exact hash matching. If a source does not expose hash values
    in a compatible type, the UI should say so plainly instead of implying a
    fuzzy match or invented malware family.
    """
    canonical_type = canonical_hash_type(record.value_type)
    if canonical_type is None:
        return {
            "applicable": False,
            "title": "Hash correlation",
            "message": "This IOC is not stored as a hash, so ThreatFox hash correlation is not applicable.",
            "matches": [],
            "families": [],
            "threat_types": [],
            "canonical_type": "",
        }

    matching_types = HASH_TYPE_ALIASES[canonical_type]
    matches = list(
        IntelIOC.objects.filter(
            source_name="threatfox",
            value_type__in=matching_types,
            value__iexact=record.value,
        )
        .order_by("-last_ingested_at", "-created_at", "-id")[:limit]
    )

    family_counter: Counter[str] = Counter()
    threat_counter: Counter[str] = Counter()
    match_rows = []

    for match in matches:
        family = str(match.malware_family or "").strip()
        threat_type = str(match.threat_type or "").strip()
        if family:
            family_counter[family] += 1
        if threat_type:
            threat_counter[threat_type] += 1

        match_rows.append(
            {
                "pk": match.pk,
                "value": match.value,
                "value_type": match.value_type,
                "malware_family": family or "Not provided",
                "threat_type": threat_type or "Not provided",
                "reporter": str(match.reporter or "").strip() or "Not provided",
                "last_ingested_at": match.last_ingested_at,
            }
        )

    family_rows = [
        {"label": label, "count": count}
        for label, count in family_counter.most_common()
    ]
    threat_rows = [
        {"label": label, "count": count}
        for label, count in threat_counter.most_common()
    ]

    if matches:
        message = "ThreatFox contains exact hash matches for this IOC. Malware-family suggestions below are evidence-backed correlations."
    else:
        message = "No exact ThreatFox hash matches were found for this IOC in the current dataset."

    return {
        "applicable": True,
        "title": "ThreatFox hash correlation",
        "message": message,
        "matches": match_rows,
        "families": family_rows,
        "threat_types": threat_rows,
        "canonical_type": canonical_type.upper(),
    }
