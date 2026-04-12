from __future__ import annotations

import os

import requests

try:
    from intel.services.env import load_project_env
except ModuleNotFoundError:  # pragma: no cover - running file directly
    from env import load_project_env

load_project_env()


URLHAUS_RECENT_URLS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def get_urlhaus_api_key() -> str | None:
    return os.getenv("URLHAUS_API_KEY")


def fetch_recent_urlhaus_iocs(timeout: int = 30) -> dict:
    """
    Fetch recent URLHaus URL records.

    URLHaus exposes recent malicious URLs publicly. An auth key can still be
    passed when available, but the integration remains usable without one.
    """
    headers = {}
    api_key = get_urlhaus_api_key()
    if api_key:
        headers["Auth-Key"] = api_key

    response = requests.get(
        URLHAUS_RECENT_URLS_ENDPOINT,
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()
