---
name: session-summaries
description: Maintain durable end-of-task session summaries for Codex work. Use when the user asks to manage changes made, capture implementation rationale, record tests and validation, preserve future task scope, create handoff notes, or save a timestamped workflow track record under .agents/session-summaries.
---

# Session Summaries

## Purpose

Use this skill to preserve a concise work trail at natural stopping points. Capture what changed, why it changed, how it was validated, and what should happen next.

Do not write private chain-of-thought. Summarize decisions, constraints, assumptions, and implementation rationale in a user-safe form.

## Summary Location

Prefer the current repository's summary folder:

`.agents/session-summaries/`

If the task is maintaining the canonical agent framework itself, use:

`C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents\session-summaries\`

Preserve `Goal.md`. Do not overwrite existing summaries.

## File Naming

Save new summaries as Markdown files with a stable timestamp:

`Summary-YYYY-MM-DD-HHMM.md`

Use local workspace time when available. If a file with the same name already exists, append seconds:

`Summary-YYYY-MM-DD-HHMMSS.md`

## When To Write

Write or update a summary when:

- the user explicitly asks for a session summary, handoff, task log, or work record
- a substantial implementation task finishes
- code, workflows, docs, or automation were changed and future continuation would benefit from a record
- validation results or unresolved risks should be easy to find later
- the user asks to preserve thought process, decisions, or scope for future tasks

For tiny one-command tasks, skip creating a summary unless the user asks.

## Workflow

1. Locate the right `.agents/session-summaries` folder for the active repo or canonical framework.
2. Read `Goal.md` if present to align with local expectations.
3. Inspect the current task outcome, changed files, tests run, blockers, and follow-up scope.
4. Create the summary directory if it does not exist.
5. Add a new timestamped summary file. Do not overwrite older summaries.
6. Keep the summary factual, concise, and useful for resuming work.
7. Mention the summary path in the final response when one is created.

## Summary Template

Use this structure unless the task calls for something narrower:

```markdown
# Summary YYYY-MM-DD HH:MM

## Task
- User request and goal.

## Changes Made
- Files, workflows, docs, or configuration changed.
- Important behavior added, removed, or preserved.

## Decisions And Rationale
- Key implementation choices.
- Constraints, assumptions, and tradeoffs.
- User-safe reasoning summary only; no private chain-of-thought.

## Validation
- Commands, tests, smoke checks, manual checks, or skipped validation.
- Relevant pass/fail details.

## Current State
- What now works.
- Known limitations, risks, or incomplete pieces.

## Future Scope
- Concrete next steps.
- Follow-up tests, refactors, docs, deployments, or review items.
```

## Writing Rules

- Keep summaries implementation-specific, not generic status prose.
- Include exact file paths when useful.
- Include test commands and outcomes exactly enough to rerun them.
- Record user-visible behavior and operational state.
- Note when validation was not run and why.
- Avoid secrets, tokens, private keys, credentials, proprietary data dumps, and hidden reasoning.
- Do not use this folder for large logs, generated artifacts, screenshots, or unrelated notes.
