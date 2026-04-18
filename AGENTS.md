# AGENTS.md

## Repository Scope

ThreatFoundry is an existing project repository. Do not treat it as a new repo bootstrap unless the user explicitly asks for that flow.

The reusable Codex agent framework for this repo lives in `.agents/`. Use `.agents/AGENTS.md` for skill discovery rules, global workspace rules, and the list of available local skills.

## Agent Workflow

- Load the matching local skill from `.agents/skills/` when a task clearly maps to one of the documented skill domains.
- Keep changes scoped to the user's current request.
- Preserve existing application code, routes, runtime behavior, dependency files, and project layout unless the requested task requires a direct change.
- Prefer small, reversible edits and explain any repository-level assumptions before broad changes.
- Do not create starter project folders, sample app code, CI, Docker, test scaffolding, or generic bootstrap files as part of routine agent work.

## Local Agent Framework

The `.agents` directory was copied from the canonical master source:

`C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents`

Required framework anchors:

- `.agents/AGENTS.md`
- `.agents/skills/`
