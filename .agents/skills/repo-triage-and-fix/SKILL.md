---
name: repo-triage-and-fix
description: Diagnose unfamiliar codebases, trace bugs from symptoms to root cause, and apply the smallest safe fix without broad refactors.
---

# Repo Triage and Fix

## Purpose

Use this skill when a repo is broken, confusing, partially understood, or newly opened.  
This skill is designed for fast orientation, reliable bug isolation, and minimal-risk repair.

## When To Use

Use this skill for tasks such as:

- reviewing a traceback or runtime error
- fixing a broken route, function, or script
- tracing an issue across templates, handlers, models, and config
- understanding an unfamiliar project before editing
- repairing something Codex or another tool changed incorrectly
- narrowing down regressions after a recent change

## Working Rules

- Start with the user’s exact error, symptom, or failing workflow.
- Trace the current behavior before proposing a fix.
- Prefer the smallest working fix over a broad cleanup.
- Preserve existing imports unless removal is necessary.
- Do not refactor unrelated files during a bug fix.
- Avoid renaming functions, routes, classes, or files unless explicitly requested.
- Make the repo easier to reason about after the fix, not more clever.

## Default Workflow

1. Identify the failing command, page, endpoint, or stack trace.
2. Locate the exact files involved in the live execution path.
3. Compare intended behavior to actual behavior.
4. Find the root cause, not just the visible symptom.
5. Apply the narrowest safe fix.
6. Re-check nearby references that could still be broken.
7. Summarize cause, fix, and manual verification path.

## Common Focus Areas

### Error Triage
- stack traces
- route mismatches
- import failures
- wrong argument names
- invalid object construction
- missing file references

### Repo Orientation
- where the app starts
- how data flows through the project
- what files actually control the feature in question
- whether the issue is frontend, backend, config, or schema-related

### Safe Fixes
- correcting references
- aligning route and template behavior
- repairing parameter flow
- adding narrowly scoped validation
- fixing path handling
- preventing obvious repeat breakage

## Output Expectations

For each task, prefer to deliver:

- exact files inspected
- root cause in plain language
- minimal fix applied
- manual steps to verify the result
- note of any remaining adjacent risk

## Avoid

- broad code cleanup during triage
- speculative rewrites
- architecture changes before understanding the bug
- deleting working code because one path is broken
