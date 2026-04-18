# Ticket Workspace

ThreatFoundry includes a lightweight analyst ticketing workspace for tracking investigation work alongside IOC review and assistant-driven analysis.

## Routes

- `/tickets/`: ticket queue, ticket creation form, and workspace tab shell.
- `/tickets/<pk>/`: ticket detail workspace.
- `/tickets/<pk>/notes/`: POST-only note submission endpoint.

All ticket routes require an authenticated user with analyst access or higher.

## Data Model

`Ticket` stores the core record:

- title
- description
- status
- priority
- created_by
- assigned_to
- created_at
- updated_at

`TicketNote` stores analyst notes:

- ticket
- body
- author
- created_at

Notes are displayed in chronological order.

## Forms and Views

Forms live in `intel/forms.py`:

- `TicketCreateForm`
- `TicketUpdateForm`
- `TicketNoteForm`

Ticket views live in `intel/views_tickets.py`:

- `ticket_list_view`
- `ticket_detail_view`
- `ticket_note_create_view`

The note endpoint is POST-only and keeps normal Django CSRF protections.

## Workspace UI

Templates:

- `intel/templates/intel/ticket_list.html`
- `intel/templates/intel/ticket_detail.html`

Static assets:

- `intel/static/intel/tickets.css`
- `intel/static/intel/tickets.js`

The detail page is structured as a three-panel analyst workspace:

- left panel: editable ticket fields
- center panel: note composer and activity feed
- right panel: record information and supporting metadata

The ticket list page provides queue filtering, ticket creation, open workspace tabs, and a safe popout control.

## Workspace Tabs

Open ticket tabs are managed client-side in `tickets.js`.

Stored browser state is intentionally minimal:

- ticket IDs
- ticket titles
- active ticket ID
- collapsed panel state
- temporary selected `status`, `priority`, and `assigned_to` values after note submission

The browser does not store note bodies, tokens, assistant prompts, system context, or privileged backend-only data.

## Popout Behavior

Popout links use normal authenticated routes with `?popout=1`. This controls layout only; it does not grant access or bypass server-side checks.

When JavaScript opens a popout window, it uses `noopener,noreferrer` and avoids cross-window messaging. No note content or internal state is placed in the URL.

## Security Notes

- Ticket pages rely on the same Django auth/session stack as the rest of the app.
- Ticket note submission uses POST and CSRF protection.
- Dynamic ticket tab rendering uses safe DOM APIs such as `createElement`, `textContent`, `classList`, `dataset`, and `replaceChildren`.
- The ticket JavaScript does not use `innerHTML`, `outerHTML`, or `insertAdjacentHTML` for dynamic ticket content.

## Validation

Recommended checks after ticket workspace changes:

```bash
python manage.py check
python manage.py test intel.tests_tickets
python manage.py test intel
git diff --check
```
