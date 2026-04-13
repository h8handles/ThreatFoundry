# WHOIS + Geolocation Enrichment POC

A clean standalone Python proof of concept for domain enrichment using WHOIS and geolocation.

This repository is designed as a lightweight enrichment component that can later be integrated into ThreatFoundry. It performs WHOIS lookup, DNS resolution, and IP geolocation enrichment in a reusable modular structure.

## Project Purpose

- Accept a domain from the command line
- Perform a WHOIS lookup using `python-whois`
- Resolve the domain to an IP address
- Enrich the resolved IP using `ip-api.com`
- Return combined, structured output as readable JSON
- Keep code modular and easy to extend into API-based enrichment services

## Project Structure

```text
whois-testing/
├── app.py
├── whois_client.py
├── geo_client.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

1. Create and activate a virtual environment (recommended):

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the CLI:

```bash
python app.py
```

You will be prompted:

```text
Enter domain: example.com
```

## Dependencies

- `python-whois` for WHOIS parsing
- `requests` for geolocation API calls
- `pytest` for local tests

## Sample Output

```json
{
  "domain": "example.com",
  "whois": {
    "domain_name": "EXAMPLE.COM",
    "registrar": "RESERVED-Internet Assigned Numbers Authority",
    "creation_date": "1995-08-14T04:00:00",
    "expiration_date": "2026-08-13T04:00:00",
    "updated_date": "2025-08-14T07:01:39",
    "name_servers": [
      "A.IANA-SERVERS.NET",
      "B.IANA-SERVERS.NET"
    ],
    "status": [
      "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited"
    ],
    "emails": [],
    "organization": "Internet Assigned Numbers Authority",
    "country": "US"
  },
  "geolocation": {
    "resolved_ip": "93.184.216.34",
    "city": "Los Angeles",
    "region": "California",
    "country": "United States",
    "latitude": 34.0544,
    "longitude": -118.244,
    "isp": "Example ISP",
    "organization": "Example Org",
    "asn": "AS15133 EdgeCast Networks, Inc."
  }
}
```

Notes:
- WHOIS fields vary by TLD and registrar; some values may be `null` or empty.
- Geolocation fields depend on DNS success and IP geolocation API response availability.

## Error Handling

- Empty domain input is rejected
- Basic domain format validation is included
- WHOIS lookup failures are captured in the `whois.error` field
- DNS resolution failures are captured in the `geolocation.error` field
- Geolocation API failures, timeout issues, and malformed responses are handled cleanly

## ThreatFoundry Direction

This standalone repository is intentionally modular so it can be migrated into a shared enrichment library or internal API component for ThreatFoundry.

## Future Roadmap

- Add HTTP API wrapper for service-to-service enrichment
- Add IOC correlation support (domain-to-IP, ASN, passive DNS links)
- Build enrichment pipelines that combine WHOIS with DNS, reputation, and threat feed data
- Add caching, retry logic, and structured logging for production workflows
