---
name: prompt-and-agent-ops
description: Design precise prompts, agent task splits, implementation scopes, and tool handoff workflows for Codex, Aider, and similar coding agents.
---

# Prompt and Agent Ops

## Purpose

Use this skill when the task is less about writing product code directly and more about structuring how coding agents should work.  
This includes prompts, task decomposition, scope boundaries, execution plans, and handoff instructions between agents or tools.

## When To Use

Use this skill for tasks such as:

- writing Codex prompts
- writing Aider prompts
- breaking a large change into smaller agent-sized tasks
- defining exact files to inspect or edit
- creating implementation plans for multi-step work
- improving prompt precision to reduce wasted runs
- creating issue-to-repro-to-fix pipelines

## Working Rules

- Keep prompts narrow and explicit.
- Separate multi-step work into clearly labeled tasks.
- Name exact files whenever possible.
- State what not to change, not just what to change.
- Preserve existing imports unless removal is necessary.
- Prefer operational wording over vague goals.
- Build prompts that reduce accidental refactors and wasted credits.

## Default Workflow

1. Identify the exact end goal.
2. Reduce it to the smallest safe agent-sized task.
3. Name the exact files, commands, or boundaries.
4. State success criteria in concrete terms.
5. Add guardrails about scope, imports, and unrelated files.
6. If the task is too large, split it into multiple prompts.
7. Provide both execution prompt and human context note when useful.

## Common Focus Areas

### Prompt Construction
- low-context prompts
- medium-context prompts
- exact file targeting
- explicit constraints
- expected output wording
- analysis-only versus edit mode prompts

### Agent Workflow Design
- repro agent
- fix agent
- review agent
- issue generation
- session creation
- artifact handling

### Scope Control
- one task at a time
- no broad refactors
- preserve repo conventions
- keep outputs diff-friendly and reviewable

## Output Expectations

For each task, prefer to deliver:

- one tightly scoped prompt or a sequence of clearly separated prompts
- explicit target files
- exact success conditions
- exact non-goals
- optional manual fix path if relevant

## Avoid

- giant all-in-one prompts
- vague instructions like "improve the app"
- hidden assumptions about repo structure
- prompts that encourage broad refactors
