# Cleanup Review Archive

Files in this directory were moved out of the active ThreatFoundry application tree during repository cleanup.

They are preserved for review instead of deleted because they may contain useful history, proof-of-concept logic, or notes, but they are not referenced by the active Django routes, installed apps, templates, static assets, or documented runtime commands.

Current contents:

- `huntfoundry/`: disabled experimental hunts prototype; not included in `INSTALLED_APPS` or URL routing.
- `legacy_helpers/threatfox.py`: legacy pointer script superseded by `python manage.py import_threatfox`.
- `notes/todo`: local checklist and manual verification notes.
