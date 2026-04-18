# Frontend Security

Use this reference when writing JavaScript, rendering dynamic UI, handling API responses, or passing Django data into browser code.

For dashboards, chat panels, popouts, IOC tables, and feed previews, assume every value returned by the server may contain attacker-controlled text unless the server proves otherwise. Render text as text by default.

## DOM Rendering

Avoid HTML sinks for untrusted data:

- `innerHTML`
- `outerHTML`
- `insertAdjacentHTML`
- `document.write`
- dynamic `<script>` creation

Prefer safe APIs:

- `textContent`
- `createElement`
- `append`
- `replaceChildren`
- allowlisted `setAttribute`

Bad:

```js
message.innerHTML = apiResponse.message;
```

Good:

```js
message.textContent = apiResponse.message;
```

## Attributes

- Do not set event handler attributes from data.
- Do not set `href`, `src`, or style values from unvalidated input.
- Allowlist URL protocols before assigning links.

Preferred URL validation:

```js
function safeHttpUrl(value) {
  const url = new URL(value, window.location.origin);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Unsupported URL protocol");
  }
  return url.href;
}
```

## JSON And API Data

- Treat API responses as untrusted until validated.
- Check object shape before rendering.
- Use default display values for missing optional fields.
- Fail closed when the response type is unexpected.

Example:

```js
function isMessage(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      typeof value.title === "string" &&
      typeof value.body === "string"
  );
}
```

## Template Data

- Prefer Django `json_script` for structured data.
- Read with `textContent`, then `JSON.parse`.
- Do not interpolate template values into JavaScript strings manually.

## Rich Text

- Do not render rich text unless the feature requires it.
- If rich text is required, use a trusted sanitizer with an allowlist.
- Keep the allowlist narrow and specific to the UI need.
- Never treat feed descriptions, IOC notes, analyst comments, or integration messages as trusted HTML.

## Event Handling

- Use `addEventListener`.
- Do not construct handlers from strings.
- Keep event payload parsing explicit.

## Storage

- Do not store secrets, session tokens, or webhook secrets in local storage.
- Treat local storage data as user-controlled.
- Validate stored data before use.

## Fetch

- Send JSON with explicit `Content-Type`.
- Handle non-2xx responses.
- Do not expose secret headers in browser code.
- Include CSRF headers for Django browser endpoints that mutate state.
