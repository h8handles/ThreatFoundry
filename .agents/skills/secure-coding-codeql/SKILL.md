---
name: secure-coding-codeql
description: Enforces secure coding practices using lessons learned from CodeQL findings in ThreatFoundry. Focuses on preventing XSS, injection, unsafe deserialization, and insecure Django and JavaScript patterns during development.
---

# PURPOSE

This skill ensures that all generated or modified code follows secure coding best practices based on real CodeQL findings and common web application vulnerabilities.

It acts as a prevention and review layer during development, especially when using AI generated code. Apply it before introducing code that moves external data from feeds, IOCs, API requests, webhook payloads, database records, or browser state into templates, DOM APIs, queries, file paths, subprocesses, or redirects.

# WHEN TO USE

Use this skill when:

- Modifying Django views, templates, or routing
- Writing JavaScript that manipulates the DOM
- Adding new API endpoints or webhook handlers
- Handling user input or external data such as IOCs, feeds, and JSON
- Building UI features like chat, popouts, and dashboards
- Reviewing CodeQL alerts or fixing vulnerabilities

# CORE SECURITY RULES

## 1. INPUT HANDLING

- Never trust user input
- Always validate and sanitize:
  - Query params
  - POST bodies
  - Headers
  - Webhook payloads

### REQUIRED PATTERNS

- Use strict schema validation for JSON
- Enforce type checking before processing
- Reject unexpected fields

## 2. XSS PREVENTION

### Django Templates

- Never use `|safe` unless absolutely required
- Prefer automatic escaping
- Use `escape` when rendering dynamic content

### JavaScript

- Never use:
  - `innerHTML`
  - `document.write`
  - dynamic script injection

- Always use:
  - `textContent`
  - `createElement`
  - safe attribute setters

## 3. DOM SECURITY

- Avoid directly injecting user controlled data into:
  - HTML
  - attributes
  - URLs

- Sanitize any dynamic rendering

## 4. API AND WEBHOOK SECURITY

- Validate all incoming webhook data
- Enforce authentication or shared secret validation
- Rate limit endpoints where possible
- Reject malformed JSON

## 5. DJANGO SECURITY PRACTICES

- Use Django ORM, never raw SQL unless parameterized
- Ensure CSRF protection is enabled where applicable
- Do not expose internal stack traces
- Validate URL parameters before use

## 6. FILE HANDLING

- Never trust uploaded file names or paths
- Validate extensions and MIME types
- Prevent directory traversal

## 7. AUTHORIZATION AND ACCESS CONTROL

- Do not assume frontend restrictions are sufficient
- Enforce permission checks server side

# CODEQL DRIVEN FIX STRATEGY

When a vulnerability is detected:

1. Identify the data source, such as user input, API, or database
2. Trace how it flows to the sink, such as DOM, query, or render
3. Break the chain using:
   - validation
   - encoding
   - safe APIs
4. Add or update a regression test where the project already has a test pattern
5. Re-run the relevant security check or CodeQL workflow when available

# AI SPECIFIC RULES

- Do not blindly generate code that:
  - injects HTML
  - trusts external APIs
  - skips validation for speed

- Always prefer:
  - explicit validation
  - defensive coding
  - predictable behavior

# OUTPUT REQUIREMENTS

When modifying code:

1. Explain the security issue briefly
2. Apply a minimal, targeted fix
3. Do not refactor unrelated code
4. Preserve existing functionality
5. Follow existing project structure
6. Mention any security checks that were run or could not be run

# REFERENCES

Load these only when relevant:

- `references/codeql-patterns.md` for source-to-sink review workflow and common CodeQL alert classes
- `references/django-secure-patterns.md` for Django views, templates, ORM, CSRF, auth, uploads, and settings
- `references/frontend-security.md` for DOM, JavaScript, JSON, URL, and browser API safety

# CHECKLIST SCRIPT

Use `scripts/security-checklist.ps1` from the repo root to scan for high-risk patterns before finishing security-sensitive work.

# EXAMPLES

## BAD

```js
element.innerHTML = userInput;
```

## GOOD

```js
element.textContent = userInput;
```

## BAD

```python
Model.objects.raw(f"SELECT * FROM app_model WHERE name = '{name}'")
```

## GOOD

```python
Model.objects.filter(name=name)
```
