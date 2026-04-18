# AGENTS.md

## Active Agent Workspace

This workspace contains reusable Codex skills designed around a practical solo builder workflow.  
These skills are intentionally generic so they can adapt across changing projects, repos, and client work.

## Skill Discovery Rules

When a task clearly matches one of the domains below, load and follow that skill before making changes.

### Available Skills

1. `repo-triage-and-fix`
   - Use for debugging unknown repos, tracing breakage, reviewing errors, finding root cause, and applying the smallest safe fix.

2. `workflow-automation-builder`
   - Use for automation systems, queue pipelines, webhook flows, local runners, orchestration logic, and agent-to-agent execution chains.

3. `mvp-feature-shipper`
   - Use for fast feature delivery in early-stage apps, CRUD flows, forms, routes, UI wiring, lightweight database work, and practical shipping.

4. `prompt-and-agent-ops`
   - Use for Codex, Aider, agent prompt design, scoped task planning, session structure, tool handoff, and multi-step implementation workflows.

5. `docs-readme-and-handoff`
   - Use for README updates, implementation docs, architecture notes, issue writeups, code annotation passes, docs coverage expansion, in-app docs dashboard surfacing, and clean project handoff material.

6. `n8n-workflow-builder`
   - Use for n8n workflow design, debugging, queue orchestration, webhook intake flows, local runner integration, and workflow validation.

7. `create-codex-workflow`
   - Use for bootstrapping a new project repo using the master `.agents` directory at `C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents`.

8. `secure-coding-codeql`
   - Use for CodeQL-driven secure coding review and prevention across Django, JavaScript, templates, APIs, webhooks, XSS, injection, deserialization, and unsafe input handling.

9. `session-summaries`
   - Use for timestamped end-of-task summaries, implementation records, validation notes, decision rationale, and future scope tracking under `.agents/session-summaries`.

## Global Workspace Rules

- Work in single-task scope unless explicitly told to do otherwise.
- Prefer small, reversible changes.
- Preserve existing imports unless removal is necessary.
- Do not refactor unrelated files.
- Keep outputs practical, implementation-ready, and easy to resume later.
- For Windows-based repos, prefer PowerShell-compatible instructions and scripts when shell choice matters.
- When editing docs, keep stakeholder readability first and place deep technical detail lower in the document.
- When multiple skills could apply, prefer the one closest to the current task rather than the overall project theme.

## Recommended Skill Selection Heuristics

- Unknown traceback, broken route, failing script, confusing repo state:
  use `repo-triage-and-fix`

- Queues, automation, webhooks, runners, background execution flows, agent pipelines:
  use `workflow-automation-builder`

- Shipping app functionality quickly, fixing forms, wiring pages, delivering MVP behavior:
  use `mvp-feature-shipper`

- Writing Codex prompts, Aider prompts, agent task splits, orchestration plans:
  use `prompt-and-agent-ops`

- README work, architecture docs, GitHub issues, handoff notes, stakeholder summaries, code annotations, or docs dashboard surfacing:
  use `docs-readme-and-handoff`

- Existing workflow JSON analysis, node validation, webhook plumbing:
  use `n8n-workflow-builder`

- New project repo bootstrap using the master `.agents` framework:
  use `create-codex-workflow`

- CodeQL findings, secure coding review, Django or JavaScript XSS prevention, injection risks, webhooks, APIs, or unsafe input handling:
  use `secure-coding-codeql`

- End-of-task summaries, saved implementation records, validation notes, decision rationale, future scope, or task handoff logs:
  use `session-summaries`
