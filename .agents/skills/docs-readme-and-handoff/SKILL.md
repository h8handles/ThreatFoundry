---
name: docs-readme-and-handoff
description: Write and update practical project documentation, annotate important code paths, and ensure docs are discoverable in project docs dashboards or in-app documentation UIs.
---

# Docs README and Handoff

## Purpose

Use this skill when the output needs to explain a project clearly to a future self, collaborator, client, or stakeholder.  
This skill focuses on useful, readable documentation that matches reality, explains important code paths, and makes the resulting docs easy to find from the product or developer-facing dashboard.

## When To Use

Use this skill for tasks such as:

- updating a README
- writing setup instructions
- creating architecture notes
- creating feature documentation in `docs/`
- preparing GitHub issue text
- documenting workflow behavior
- documenting tickets, analyst assistants, automations, integrations, security flows, or dashboards
- adding concise docstrings or comments to important code paths
- exposing new or renamed docs in an in-app documentation dashboard
- writing handoff summaries
- translating technical work into client-friendly language
- keeping docs aligned after changes

## Working Rules

- Keep the top of the document readable for non-experts.
- Move deep technical detail lower in the file.
- Reflect actual behavior, not aspirational behavior.
- Use concrete commands, file names, and flows when available.
- Prefer crisp structure over long narrative.
- Update examples when commands or entry points change.
- Keep docs useful for resuming work later.
- Preserve existing docs structure, tone, and naming unless the current structure is actively misleading.
- Prefer targeted updates over rewriting entire documents.
- Detect and correct stale project names, renamed features, outdated commands, and obsolete routes.
- Add documentation for real implemented behavior before documenting planned behavior.
- Annotate important code only where the explanation reduces future risk or speeds maintenance.
- Do not add comments to trivial wrappers, obvious property accessors, simple render calls, or one-line pass-through functions.
- Do not refactor unrelated code while documenting it.
- When a project has an in-app docs dashboard, ensure new docs appear through the existing discovery mechanism before adding custom registration logic.
- For ThreatFoundry work, treat in-app docs dashboard visibility as part of the definition of done for any new or renamed `docs/` file.

## Default Workflow

1. Identify the audience for the document and whether the task requires docs only, code annotations, dashboard surfacing, or all three.
2. Inventory existing docs with `rg --files` and filter for `docs/`, `README*`, `AGENTS.md`, or the closest repo-specific equivalents.
3. Inspect the current implementation paths before editing docs:
   - routes, views, templates, or frontend pages
   - services and integrations
   - workflow or automation entry points
   - security-sensitive request handling, authentication, authorization, parsing, or webhook logic
4. Detect stale naming, outdated commands, mismatched route names, obsolete feature descriptions, and docs that describe behavior no longer present in code.
5. Update existing docs selectively so they reflect the current architecture, features, setup, usage, and operational limits.
6. Create new Markdown files in `docs/` only for implemented features or workflows that lack a clear home.
7. Add concise docstrings or comments to key functions where intent, inputs, outputs, side effects, or security implications are not obvious.
8. Verify docs dashboard discovery:
   - find the existing docs index, loader, manifest, route, template, or filesystem scan
   - confirm new docs are picked up automatically
   - extend the existing discovery path only if a real gap prevents surfacing
   - for ThreatFoundry, check the in-app docs dashboard path or its backing discovery code before considering the task complete
9. Run focused validation where available, such as docs route smoke checks, unit tests around docs loading, or static checks for touched code.
10. Summarize docs updated, docs created, functions annotated, dashboard integration changes, and validation performed.

## Common Focus Areas

### README Structure
- what the project is
- why it exists
- current workflow
- installation
- usage
- file structure
- roadmap

### Documentation Refresh
- current project and product names
- current architecture and feature set
- setup commands that still work
- environment variables and service dependencies
- routes, dashboards, background jobs, and workflow names
- links between README, `docs/`, and in-app docs

### Feature Docs
- ticket lifecycle and analyst workflows
- assistant or agent behavior
- webhook and queue processing
- n8n or local runner orchestration
- integrations and external service assumptions
- security review, auth, permissions, and data handling

Create a new doc when an implemented feature has no obvious documentation home, when existing docs would become overloaded, or when a dashboard needs a standalone page for discoverability. Update an existing doc when the feature already belongs to that page and only the details are stale.

### Handoff Material
- what was done
- what remains
- known risks
- how to resume
- how to validate the system

### Code Annotation
- public or widely reused service functions
- view/controller functions with non-obvious branching
- integrations that call external systems or mutate remote state
- security-sensitive logic such as webhook verification, input parsing, permissions, auth, secrets, file handling, and command execution
- workflow orchestration where side effects cross process, queue, or network boundaries

For annotations, include only the useful facts:

- purpose
- important inputs
- return value or output shape
- side effects such as database writes, network calls, queue messages, files, or audit events
- security assumptions or caller responsibilities

### Communication Assets
- GitHub issues
- implementation summaries
- internal notes
- client-facing explanations
- technical comments rewritten for clarity

### Docs Dashboard Surfacing
- docs discovery helpers
- docs manifests or navigation registries
- routes that read Markdown from `docs/`
- templates/components that list docs
- tests or smoke checks that prove new docs are visible

Prefer the project's current dashboard pattern. Common safe changes include adding front matter expected by the loader, placing the file under the scanned directory, updating an existing manifest entry, or extending a filter to include the new category. Avoid replacing filesystem discovery, route handlers, or navigation components unless they are demonstrably unable to surface the new docs.

## Output Expectations

For each task, prefer to deliver:

- a clean Markdown file or section update
- new docs in `docs/` only when there is a real coverage gap
- concise docstrings/comments on important code paths
- dashboard discovery or registration updates when needed
- accurate commands and file names
- clear audience-appropriate wording
- practical next steps if needed
- no fluff that hides the real state of the project

When the task includes a full docs workflow, the final response should include:

- docs updated
- new docs created
- functions annotated
- docs dashboard integration changes
- validation performed or skipped

## Avoid

- docs that sound polished but are inaccurate
- giant walls of text
- unexplained acronyms at the top of the document
- roadmap claims unsupported by the current implementation
- rewriting every doc to impose a new style
- broad code cleanup while adding annotations
- comments that restate obvious code
- adding a second docs discovery system when an existing one can be extended
