# Django Secure Patterns

Use this reference for Django views, routes, templates, API handlers, webhook endpoints, uploads, auth, and settings.

## Views And APIs

- Validate request method explicitly.
- Parse JSON with clear error handling.
- Reject malformed JSON with `400 Bad Request`.
- Enforce required fields and reject unexpected fields.
- Convert and validate IDs before database access.
- Use server-side permission checks before returning data or mutating state.
- Validate IOC, feed, alert, and integration payload fields before persistence.

Preferred JSON flow:

```python
import json
from django.http import JsonResponse

ALLOWED_FIELDS = {"name", "description"}

def parse_payload(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, JsonResponse({"error": "Invalid JSON"}, status=400)

    if not isinstance(payload, dict):
        return None, JsonResponse({"error": "Expected JSON object"}, status=400)

    unknown = set(payload) - ALLOWED_FIELDS
    if unknown:
        return None, JsonResponse({"error": "Unexpected fields"}, status=400)

    return payload, None
```

## Templates

- Prefer Django autoescaping.
- Avoid `|safe` for user or external data.
- Use `escape` when forcing text into a sensitive context.
- Do not build JavaScript literals from unescaped template variables.
- Use `json_script` for passing structured data to JavaScript.

Preferred JSON-to-JavaScript flow:

```django
{{ payload|json_script:"payload-data" }}
```

```js
const payload = JSON.parse(document.getElementById("payload-data").textContent);
```

## ORM And Queries

- Prefer Django ORM methods.
- Use allowlists for dynamic sort, filter, and field names.
- If raw SQL is necessary, use parameters and keep SQL fragments static.

Bad:

```python
cursor.execute(f"SELECT * FROM app_item WHERE name = '{name}'")
```

Good:

```python
cursor.execute("SELECT * FROM app_item WHERE name = %s", [name])
```

## CSRF

- Keep CSRF protection enabled for browser-submitted state changes.
- Do not apply `csrf_exempt` unless the endpoint is a true external webhook.
- For webhooks, replace CSRF with signed secret verification and strict payload validation.

## Webhooks

- Require a shared secret or signature.
- Compare secrets with constant-time comparison.
- Reject missing or malformed signature headers.
- Limit payload size where possible.
- Validate event type against an allowlist.
- Return generic errors that do not reveal internals.
- Do not trust webhook timestamps, IDs, URLs, or nested JSON without schema checks.

Preferred signature comparison:

```python
from django.utils.crypto import constant_time_compare

if not constant_time_compare(received_signature, expected_signature):
    return JsonResponse({"error": "Unauthorized"}, status=401)
```

## Redirects

- Never redirect directly to a user-provided URL.
- Use `url_has_allowed_host_and_scheme` for return URLs.
- Prefer named routes where possible.

## Uploads And Files

- Generate storage names server side.
- Do not trust `UploadedFile.name`.
- Validate extension and MIME type.
- Enforce size limits.
- Store uploads outside executable paths.
- Normalize paths and ensure they remain inside the expected base directory.

## Settings And Errors

- Keep `DEBUG = False` outside local development.
- Do not expose stack traces to users.
- Keep secrets in environment variables or a secret store.
- Set secure cookie flags for production.
- Use HTTPS and secure proxy settings when deployed behind a proxy.
