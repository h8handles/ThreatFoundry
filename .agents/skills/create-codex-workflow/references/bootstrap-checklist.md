# Bootstrap Checklist

## New Repo Bootstrap Steps

1. Resolve the target project path to an absolute path.
2. Derive or confirm the project name from the target folder.
3. Create the target project root if it does not exist.
4. Choose a minimal layout for the project type.
5. Create starter directories only when useful for the project.
6. Copy the complete master `.agents` folder from `C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents` into the project root as `.agents`.
7. Verify the copied agent framework.
8. Leave existing destination files untouched unless the user explicitly approved overwrite behavior.

## Required Directories

Every bootstrapped project should contain:

- `.agents`
- `.agents\AGENTS.md`
- `.agents\skills`

Common optional directories:

- `src`
- `docs`
- `scripts`
- `tests`
- `prompts`

## Validation Checklist After Copy

Run these checks after copying:

```powershell
Test-Path "$TargetRepoPath\.agents"
Test-Path "$TargetRepoPath\.agents\AGENTS.md"
Test-Path "$TargetRepoPath\.agents\skills"
Get-ChildItem "$TargetRepoPath\.agents\skills" -Directory
```

Confirm:

- `.agents\AGENTS.md` exists.
- `.agents\skills\` exists and contains the expected master skills.
- The copy preserved nested reference and script folders.
- The target repo did not receive a duplicate `AGENTS.md` outside `.agents`.
- Existing project files were not overwritten unless the user requested it.

## Common Mistakes To Avoid

- Copying from a non-master `.agents` folder.
- Copying only `AGENTS.md` without `skills`.
- Creating `.agents` under `src`, `docs`, or another nested folder.
- Overwriting a destination `.agents` folder without explicit permission.
- Renaming skills during bootstrap.
- Adding project-specific TODO placeholders that do not help the first implementation task.
