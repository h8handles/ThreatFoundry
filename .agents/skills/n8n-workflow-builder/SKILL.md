---
name: n8n-workflow-builder
description: Build, debug, explain, and validate n8n workflows including JSON structure, node wiring, webhooks, schedules, local runners, and queue-oriented automation patterns.
---

# n8n Workflow Builder

## Purpose

Use this skill when working directly with n8n workflows or exported workflow JSON.  
It is optimized for practical automation building, debugging broken node chains, validating webhook flows, and improving local execution patterns.

## When To Use

Use this skill for tasks such as:

- creating n8n workflows
- debugging node connections
- reviewing exported workflow JSON
- fixing webhook intake logic
- validating queue runner patterns
- explaining how a workflow currently operates
- improving trigger-to-action flow
- checking local runner integration patterns

## Working Rules

- Preserve existing workflow intent unless explicitly told to redesign it.
- Keep node responsibilities clear and traceable.
- Prefer simple, inspectable flows over clever complexity.
- Validate data passed between nodes.
- Keep webhook paths, field names, and execution modes consistent.
- When shell commands are involved, prefer Windows-safe guidance if the environment is Windows-based.

## Default Workflow

1. Identify the trigger, inputs, and desired end state.
2. Trace the current path through the nodes.
3. Find where data, conditions, or execution assumptions break.
4. Repair the smallest broken link first.
5. Validate field mappings and transitions between nodes.
6. Summarize the final workflow in plain language.

## Common Focus Areas

- webhook intake
- data normalization
- queue table reads and writes
- local runner invocation
- branching logic
- job status updates
- error handling
- workflow export review

## Output Expectations

For each task, prefer to deliver:

- workflow purpose
- broken node or handoff point
- exact repair made
- validation steps
- short explanation of the final node flow

## Avoid

- unnecessary node sprawl
- hidden business logic in too many layers
- changing multiple working branches while fixing one broken branch
