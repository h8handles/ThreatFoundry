import json
import os

import requests
from datetime import datetime, timedelta, timezone

try:
    from intel.services.env import load_project_env
except ModuleNotFoundError:  # Running this file directly keeps imports local.
    from env import load_project_env

load_project_env()

def get_otx_api_key() -> str | None:
    """
    Read the OTX API key from the environment.

    We support the old variable name as a fallback so local setups do not break
    while the project settles on one naming convention.
    """
    return os.getenv("OTX_API_KEY") or os.getenv("OTX_API")

def fetch_otx_iocs(days: int = 1, timeout: int = 30) -> dict:
    """
    Fetch recent IOCs directly from the OTX API.

    This function only handles the HTTP request and returns the raw API payload.
    Parsing and database storage happen elsewhere so each step stays easy to
    read and test.
    """
    api_key = get_otx_api_key()
    if not api_key:
        raise RuntimeError(
            "OTX API key not found. Set OTX_API_KEY in your environment."
        )

    response = requests.get(
        "https://otx.alienvault.com/api/v1/indicators/export",
        headers={
            "X-OTX-API-KEY": api_key,
        },
        params={
            "limit": 1000,  # Adjust as needed; OTX may have pagination limits
            "type": "all",  # Fetch all types of IOCs; adjust if you want specific types
            "created_after": (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def format_otx_payload(payload: dict) -> str:
    """Return readable JSON for local CLI debugging."""
    return json.dumps(payload, indent=2, sort_keys=True)

if __name__ == "__main__":
    try:
        iocs = fetch_otx_iocs(days=1)
        print("Fetched OTX IOCs:")
        print(format_otx_payload(iocs))
        print(f"Successfully fetched {len(iocs.get('results', []))} IOCs from OTX.")
    except Exception as e:
        print("Error fetching OTX IOCs:", str(e))
