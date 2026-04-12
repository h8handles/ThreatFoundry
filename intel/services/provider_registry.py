from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _first_text(*values) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _normalize_value_type(value_type: str | None) -> str:
    return _first_text(value_type).lower().replace(" ", "").replace("_", "").replace("-", "")


def _indicator_kind(value_type: str | None) -> str:
    normalized = _normalize_value_type(value_type)
    if normalized in {"filehashmd5", "filehashsha1", "filehashsha256", "md5hash", "sha1hash", "sha256hash"}:
        return "file"
    if normalized in {"domain", "hostname"}:
        return "domain"
    if normalized in {"ip", "ipv4", "ipv6"}:
        return "ip"
    if normalized == "ip:port".replace(":", ""):
        return "ip"
    if normalized == "url":
        return "url"
    if normalized == "cve":
        return "cve"
    return ""


def _extract_ip_only(value: str) -> str:
    text = _first_text(value)
    if ":" in text and text.count(":") == 1:
        return text.split(":", 1)[0].strip()
    return text


@dataclass(frozen=True)
class ExternalLink:
    provider: str
    label: str
    url: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "label": self.label,
            "url": self.url,
            "note": self.note,
        }


@dataclass(frozen=True)
class ProviderAvailability:
    key: str
    label: str
    category: str
    enabled: bool
    missing_env_vars: tuple[str, ...]
    note: str = ""


LinkBuilder = Callable[..., list[ExternalLink]]


@dataclass(frozen=True)
class ProviderSpec:
    key: str
    label: str
    category: str
    required_env_vars: tuple[str, ...] = ()
    optional_env_vars: tuple[str, ...] = ()
    enabled_by_default: bool = False
    note: str = ""
    link_builder: LinkBuilder | None = None

    @property
    def toggle_env_var(self) -> str:
        return f"{self.key.upper()}_ENABLED"

    def missing_env_vars(self) -> tuple[str, ...]:
        return tuple(name for name in self.required_env_vars if not _first_text(os.getenv(name)))

    def is_enabled(self) -> bool:
        if not _env_flag(self.toggle_env_var, True):
            return False
        if self.required_env_vars:
            return not self.missing_env_vars()
        return self.enabled_by_default or not self.required_env_vars

    def availability(self) -> ProviderAvailability:
        return ProviderAvailability(
            key=self.key,
            label=self.label,
            category=self.category,
            enabled=self.is_enabled(),
            missing_env_vars=self.missing_env_vars(),
            note=self.note,
        )


def _build_threatfox_links(*, value: str, value_type: str, source_record_id: str = "", reference_url: str = "", **kwargs) -> list[ExternalLink]:
    direct_url = _first_text(reference_url)
    if direct_url.startswith("http"):
        return [ExternalLink(provider="threatfox", label="ThreatFox record", url=direct_url)]

    record_id = _first_text(source_record_id)
    if record_id.isdigit():
        return [
            ExternalLink(
                provider="threatfox",
                label="ThreatFox record",
                url=f"https://threatfox.abuse.ch/ioc/{record_id}/",
            )
        ]
    return []


def _build_alienvault_links(*, value: str, value_type: str, reference_url: str = "", **kwargs) -> list[ExternalLink]:
    direct_url = _first_text(reference_url)
    if direct_url.startswith("http"):
        return [ExternalLink(provider="alienvault", label="AlienVault OTX reference", url=direct_url)]

    kind = _indicator_kind(value_type)
    if not kind:
        return []

    path_kind = {
        "domain": "domain",
        "ip": "ip",
        "url": "url",
        "file": "file",
    }.get(kind)
    if not path_kind:
        return []

    return [
        ExternalLink(
            provider="alienvault",
            label="AlienVault OTX indicator",
            url=f"https://otx.alienvault.com/indicator/{path_kind}/{quote(_first_text(value))}",
        )
    ]


def _build_urlhaus_links(*, value: str, value_type: str, source_record_id: str = "", reference_url: str = "", **kwargs) -> list[ExternalLink]:
    direct_url = _first_text(reference_url)
    if direct_url.startswith("http"):
        return [ExternalLink(provider="urlhaus", label="URLhaus reference", url=direct_url)]

    kind = _indicator_kind(value_type)
    text_value = _first_text(value)
    if kind == "url" and _first_text(source_record_id).isdigit():
        return [
            ExternalLink(
                provider="urlhaus",
                label="URLhaus URL record",
                url=f"https://urlhaus.abuse.ch/url/{source_record_id}/",
            )
        ]
    if kind == "domain":
        return [
            ExternalLink(
                provider="urlhaus",
                label="URLhaus host record",
                url=f"https://urlhaus.abuse.ch/host/{quote(text_value)}/",
            )
        ]
    return []


def _build_virustotal_links(
    *,
    value: str,
    value_type: str,
    enrichment_summary: dict | None = None,
    reference_url: str = "",
    **kwargs,
) -> list[ExternalLink]:
    summary = enrichment_summary or {}
    kind = _first_text(summary.get("object_type")) or _indicator_kind(value_type)
    object_id = _first_text(summary.get("object_id"))
    lookup_value = _first_text(summary.get("lookup_value"), value)

    if kind == "file":
        token = object_id or lookup_value
        if token:
            return [
                ExternalLink(
                    provider="virustotal",
                    label="VirusTotal file page",
                    url=f"https://www.virustotal.com/gui/file/{quote(token)}/detection",
                    note="May require a VirusTotal sign-in for full context.",
                )
            ]
    if kind == "domain":
        token = object_id or lookup_value
        if token:
            return [
                ExternalLink(
                    provider="virustotal",
                    label="VirusTotal domain page",
                    url=f"https://www.virustotal.com/gui/domain/{quote(token)}/detection",
                    note="May require a VirusTotal sign-in for full context.",
                )
            ]
    if kind in {"ip_address", "ip"}:
        token = object_id or _extract_ip_only(lookup_value)
        if token:
            return [
                ExternalLink(
                    provider="virustotal",
                    label="VirusTotal IP page",
                    url=f"https://www.virustotal.com/gui/ip-address/{quote(token)}/detection",
                    note="May require a VirusTotal sign-in for full context.",
                )
            ]
    if kind == "url":
        token = object_id
        if token:
            return [
                ExternalLink(
                    provider="virustotal",
                    label="VirusTotal URL page",
                    url=f"https://www.virustotal.com/gui/url/{quote(token)}/detection",
                    note="May require a VirusTotal sign-in for full context.",
                )
            ]
    return []


def _build_abuseipdb_links(*, value: str, value_type: str, **kwargs) -> list[ExternalLink]:
    if _indicator_kind(value_type) != "ip":
        return []
    ip_value = _extract_ip_only(value)
    if not ip_value:
        return []
    return [
        ExternalLink(
            provider="abuseipdb",
            label="AbuseIPDB IP check",
            url=f"https://www.abuseipdb.com/check/{quote(ip_value)}",
        )
    ]


def _build_shodan_links(*, value: str, value_type: str, **kwargs) -> list[ExternalLink]:
    if _indicator_kind(value_type) != "ip":
        return []
    ip_value = _extract_ip_only(value)
    if not ip_value:
        return []
    return [
        ExternalLink(
            provider="shodan",
            label="Shodan host page",
            url=f"https://www.shodan.io/host/{quote(ip_value)}",
            note="Some Shodan details may require sign-in.",
        )
    ]


PROVIDER_SPECS: dict[str, ProviderSpec] = {
    "threatfox": ProviderSpec(
        key="threatfox",
        label="ThreatFox",
        category="ingestion",
        required_env_vars=("THREATFOX_API_KEY",),
        note="Community IOC ingestion from abuse.ch.",
        link_builder=_build_threatfox_links,
    ),
    "urlhaus": ProviderSpec(
        key="urlhaus",
        label="URLhaus",
        category="ingestion",
        optional_env_vars=("URLHAUS_API_KEY",),
        enabled_by_default=True,
        note="Public malware URL ingestion from abuse.ch.",
        link_builder=_build_urlhaus_links,
    ),
    "alienvault": ProviderSpec(
        key="alienvault",
        label="AlienVault OTX",
        category="ingestion",
        required_env_vars=("OTX_API_KEY",),
        note="OTX indicator ingestion requires an API key.",
        link_builder=_build_alienvault_links,
    ),
    "virustotal": ProviderSpec(
        key="virustotal",
        label="VirusTotal",
        category="enrichment",
        required_env_vars=("VIRUSTOTAL_API_KEY",),
        note="VirusTotal enrichment is quota-limited and may require sign-in for full UI context.",
        link_builder=_build_virustotal_links,
    ),
    "abuseipdb": ProviderSpec(
        key="abuseipdb",
        label="AbuseIPDB",
        category="enrichment",
        required_env_vars=("ABUSEIPDB_API_KEY",),
        note="IP reputation enrichment.",
        link_builder=_build_abuseipdb_links,
    ),
    "shodan": ProviderSpec(
        key="shodan",
        label="Shodan",
        category="enrichment",
        required_env_vars=("SHODAN_API_KEY",),
        note="Host enrichment for IP indicators.",
        link_builder=_build_shodan_links,
    ),
    "cisa_kev": ProviderSpec(
        key="cisa_kev",
        label="CISA KEV",
        category="vulnerability_intel",
        enabled_by_default=True,
        note="Public feed; no API key required for baseline usage.",
    ),
    "cve": ProviderSpec(
        key="cve",
        label="CVE Feed",
        category="vulnerability_intel",
        enabled_by_default=True,
        note="Public CVE feed support can be extended without secrets.",
    ),
    "nvd": ProviderSpec(
        key="nvd",
        label="NVD",
        category="vulnerability_intel",
        optional_env_vars=("NVD_API_KEY",),
        enabled_by_default=True,
        note="NVD can run without an API key, though an API key improves quota.",
    ),
    "mitre_attack": ProviderSpec(
        key="mitre_attack",
        label="MITRE ATT&CK",
        category="ttp_intel",
        enabled_by_default=True,
        note="Structure ready for ATT&CK mapping data.",
    ),
    "threat_actor_mapping": ProviderSpec(
        key="threat_actor_mapping",
        label="Threat Actor Mapping",
        category="ttp_intel",
        enabled_by_default=False,
        note="Architecture placeholder only; no free canonical actor feed is wired as active functionality yet.",
    ),
    # Domain enrichment provider – used by the new domain enrichment service
    "domain_enrichment": ProviderSpec(
        key="domain_enrichment",
        label="Domain Enrichment",
        category="enrichment",
        required_env_vars=("WHOIS_API_KEY",),
        note="Enrich domain IOCs with WHOIS, DNS, SSL, and reputation data.",
        link_builder=None,
    ),
}


def get_provider_spec(provider_name: str | None) -> ProviderSpec | None:
    return PROVIDER_SPECS.get(_first_text(provider_name).lower())


def get_provider_availabilities() -> list[ProviderAvailability]:
    return [spec.availability() for spec in PROVIDER_SPECS.values()]


def build_provider_links(
    provider_name: str | None,
    *,
    value: str,
    value_type: str,
    source_record_id: str = "",
    reference_url: str = "",
    enrichment_summary: dict | None = None,
) -> list[dict]:
    spec = get_provider_spec(provider_name)
    if spec is None or spec.link_builder is None:
        return []

    links = spec.link_builder(
        value=value,
        value_type=value_type,
        source_record_id=source_record_id,
        reference_url=reference_url,
        enrichment_summary=enrichment_summary or {},
    )
    unique: dict[str, ExternalLink] = {}
    for link in links:
        if link.url and link.url not in unique:
            unique[link.url] = link
    return [link.as_dict() for link in unique.values()]
