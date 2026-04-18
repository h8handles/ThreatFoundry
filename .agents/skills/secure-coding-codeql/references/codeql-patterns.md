# CodeQL Patterns

Use this reference when reviewing CodeQL alerts, tracing a suspected vulnerability, or writing code that touches untrusted input.

ThreatFoundry-style data commonly enters through API requests, webhook payloads, external feeds, IOC imports, analyst notes, chat-like UI state, and stored records later rendered into dashboards or popouts. Treat stored records as untrusted if they originated outside the server's trusted code path.

## Review Workflow

1. Identify the source.
   - HTTP query parameters
   - POST bodies
   - JSON payloads
   - Headers
   - Cookies
   - Webhook bodies
   - External feeds
   - Database fields originally populated from users or third parties

2. Identify the sink.
   - Template rendering
   - DOM insertion
   - SQL execution
   - Shell execution
   - File path construction
   - Redirect URLs
   - Deserialization
   - Logging sensitive data

3. Trace transformations.
   - Confirm whether validation is strict or cosmetic
   - Confirm whether encoding happens at the correct output boundary
   - Confirm whether allowlists are enforced before the sink

4. Break the flow.
   - Validate data shape and type
   - Reject unexpected fields
   - Encode for the target context
   - Replace unsafe APIs with safe APIs
   - Add server-side authorization checks

## Common Alert Classes

### XSS

Risky patterns:

- Django `|safe` on data that can contain user or external content
- JavaScript `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or `document.write`
- Dynamic attribute or URL injection
- Markdown or rich text rendering without sanitization
- Injecting IOC values, feed names, comments, or chat messages into templates or popouts

Safer patterns:

- Django automatic escaping
- `textContent` for text
- `createElement` and `setAttribute` with allowlisted attributes
- Sanitized rich text only when the product explicitly requires HTML

### SQL Injection

Risky patterns:

- String-formatted SQL
- Concatenated SQL fragments built from request data
- Raw ORM calls without parameters

Safer patterns:

- Django ORM filters and query expressions
- Parameterized raw SQL only when ORM is not suitable
- Allowlisted sort and filter fields

### Path Traversal

Risky patterns:

- Joining user-provided file names directly to server paths
- Trusting upload names
- Serving arbitrary paths from query parameters

Safer patterns:

- Generate server-side file names
- Normalize and verify paths stay inside the expected base directory
- Allowlist extensions and content types

### Unsafe Deserialization

Risky patterns:

- `pickle.loads` on request data or untrusted storage
- YAML load APIs that construct arbitrary objects
- Dynamic imports or eval-style behavior from payloads

Safer patterns:

- JSON with strict schema validation
- Safe YAML loaders only when YAML is required
- Explicit dispatch maps instead of dynamic evaluation

### Command Injection

Risky patterns:

- `shell=True` with request-controlled values
- Building command strings from user input
- Passing unchecked file names, URLs, or flags to subprocesses

Safer patterns:

- Argument arrays with `shell=False`
- Allowlisted command options
- Separate validation for paths, URLs, and IDs

## Fix Expectations

- Prefer the smallest fix that breaks the vulnerable data flow.
- Add regression tests around the source, sink, and rejected malicious input.
- Keep unrelated refactors out of the security patch.
- Document any accepted residual risk in the final response.
- Re-run CodeQL, the local checklist, or targeted tests when available.
