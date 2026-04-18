---
name: create-codex-workflow
description: Bootstrap a brand new project repository for Codex or agent-driven development by creating a repo skeleton, copying the canonical master .agents framework from C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents, and validating that AGENTS.md and skills are present. Use when starting new Python tools, web apps, automation projects, APIs, MVPs, or local experiments that should inherit the master agent setup.
---

# Create Codex Workflow

## Purpose

Use this skill to prepare a new project repository for future Codex or agent-driven development.
The new repository should inherit the complete master `.agents` framework from:

`C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents`

This path is the canonical template source. Do not substitute another `.agents` source path unless the user explicitly overrides it for a one-off operation.

## When To Use

Use this skill when the user wants to:

- start a brand new project repository
- create a reusable repo skeleton
- copy the master `.agents` framework into a new project
- prepare a project for Codex, Aider, or other agent workflows
- standardize new Python tools, web apps, automation projects, APIs, MVPs, or local experiments

## Required Inputs

- `TargetRepoPath`: absolute or relative path to the new project root
- `ProjectName`: human-readable project name, usually derived from the target folder name

## Optional Inputs

- `ProjectType`: `python`, `web`, `automation`, `api`, `mvp`, or `generic`
- `CreateStarterDirs`: whether to create common starter folders such as `src`, `docs`, `scripts`, `tests`, and `prompts`
- `Force`: whether to overwrite existing `.agents` files in the destination
- `MasterAgentsPath`: optional override, defaulting to `C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents`

## Default Master Source Path

Always default to:

`C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents`

New repos inherit from this master `.agents` directory. Keep this path explicit in commands, scripts, and handoff notes so future Codex runs understand where the template came from.

## Workflow

1. Confirm the target project path and project name.
2. Create the target project root if it does not exist.
3. Create a minimal repo skeleton appropriate for the project type.
4. Copy the complete master `.agents` folder into `<TargetRepoPath>\.agents`.
5. Preserve the internal `.agents` structure, including `AGENTS.md`, `skills`, references, and scripts.
6. Avoid overwriting destination files unless the user explicitly requested `Force`.
7. Validate that the new project contains:
   - `<TargetRepoPath>\.agents\AGENTS.md`
   - `<TargetRepoPath>\.agents\skills\`
8. Summarize the created structure and any credential, tooling, or manual initialization assumptions.

## Bundled Resources

- Read `references/bootstrap-checklist.md` when planning or verifying a full bootstrap.
- Read `references/repo-layout-patterns.md` when choosing starter directories by project type.
- Read `references/agent-bootstrap-rules.md` before copying into a non-empty destination.
- Use `scripts/copy-master-agents.ps1` to copy the canonical master `.agents` folder safely.
- Use `scripts/new-project-bootstrap-example.ps1` as a reusable example for creating a project root, starter folders, and copied `.agents` framework.

## Safety And Overwrite Rules

- Treat `C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents` as the source of truth.
- Do not partially copy `.agents` unless the user explicitly asks for a partial copy.
- Do not create a second `AGENTS.md` somewhere else in the target repo as part of this skill.
- Do not overwrite an existing destination `.agents` folder by default.
- If a destination `.agents` folder exists, stop and ask whether to merge, replace, or skip unless the user already provided a clear `Force` instruction.
- Preserve node, skill, and file names from the master copy.
- Keep starter repo files minimal; avoid framework-specific scaffolding unless the user asked for it.

## Example Usage

Create a new local automation project and copy in the master `.agents` framework:

```powershell
$target = "C:\Users\ghbub\OneDrive\Desktop\projects\invoice-automation"
New-Item -ItemType Directory -Force -Path $target | Out-Null
New-Item -ItemType Directory -Force -Path "$target\src", "$target\docs", "$target\scripts", "$target\tests", "$target\prompts" | Out-Null
.\.agents\skills\create-codex-workflow\scripts\copy-master-agents.ps1 -TargetRepoPath $target
```

Expected result:

```text
invoice-automation\
  .agents\
    AGENTS.md
    skills\
  src\
  docs\
  scripts\
  tests\
  prompts\
```

## Output Expectations

When finished, report:

- target project path
- master `.agents` source path used
- directories created
- whether `.agents\AGENTS.md` and `.agents\skills\` were verified
- any files skipped because they already existed
