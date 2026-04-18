---
name: workflow-automation-builder
description: Build and debug practical automation systems including queues, webhooks, runners, orchestration logic, and agent execution pipelines.
---

# Workflow Automation Builder

## Purpose

Use this skill when building or repairing automation pipelines that connect tools, agents, scripts, APIs, queues, and execution runners.  
This skill is meant for practical local-first automation that can grow over time.

## When To Use

Use this skill for tasks such as:

- webhook intake flows
- queue design and job state handling
- local execution runners
- n8n-adjacent orchestration
- agent chaining
- prompt-to-execution automation
- claim, run, complete, retry pipelines
- PowerShell or Python glue between systems

## Working Rules

- Keep the flow explicit and easy to debug.
- Favor visible state transitions over hidden automation magic.
- Preserve current endpoints and field names unless the task requires change.
- Prefer idempotent steps where possible.
- Design for retry and inspection, not just happy-path execution.
- Keep local and Windows-compatible execution in mind when shell choice matters.
- Separate intake, persistence, execution, and completion concerns clearly.

## Default Workflow

1. Identify the current workflow stages.
2. Map the data passed between each stage.
3. Find where jobs are lost, malformed, duplicated, or stuck.
4. Repair the smallest broken stage first.
5. Tighten validation around the handoff boundary.
6. Confirm the full path from intake to completion.
7. Document the resulting flow in simple operational terms.

## Common Focus Areas

### Pipeline Design
- intake webhook
- normalization
- queue persistence
- claim logic
- runner execution
- result reporting
- cleanup and retention

### Reliability
- missing fields
- job status drift
- duplicate execution
- connection assumptions
- broken runner commands
- timeout or retry gaps

### Agent Workflows
- prompt packaging
- execution scope
- chaining outputs into next-step inputs
- audit checkpoints
- human review gates

### Local Runner Integration
- PowerShell invocation
- repo path targeting
- environment variable handling
- CLI argument construction
- result capture

## Output Expectations

For each task, prefer to deliver:

- workflow stages
- exact breakage point
- data shape or field issue if relevant
- smallest safe repair
- suggested operational validation path
- brief description of final flow

## Avoid

- overengineering early pipelines
- hiding state in too many layers
- changing multiple workflow stages at once unless necessary
- assuming cloud dependencies when local-first is viable
