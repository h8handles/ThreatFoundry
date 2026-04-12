import os

import requests

try:
    from intel.services.env import load_project_env
except ModuleNotFoundError:  # Running this file directly keeps imports local.
    from env import load_project_env

load_project_env()


# Single source of truth for the ThreatFox endpoint.
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def get_threatfox_api_key() -> str | None:
    """
    Read the API key from the environment.

    We support the old variable name as a fallback so local setups do not break
    while the project settles on one naming convention.
    """
    return os.getenv("THREATFOX_API_KEY") or os.getenv("THREAT_FOX_API")


def fetch_threatfox_iocs(days: int = 1, timeout: int = 30) -> dict:
    """
    Fetch recent IOCs directly from ThreatFox.

    This function only handles the HTTP request and returns the raw API payload.
    Parsing and database storage happen elsewhere so each step stays easy to
    read and test.
    """
    api_key = get_threatfox_api_key()
    if not api_key:
        raise RuntimeError(
            "ThreatFox API key not found. Set THREATFOX_API_KEY in your environment."
        )

    response = requests.post(
        THREATFOX_API_URL,
        headers={
            "Auth-Key": api_key,
            "Content-Type": "application/json",
        },
        json={
            "query": "get_iocs",
            "days": days,
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()
