# Agent Bootstrap Rules

## Canonical Source

The permanent master source path is:

`C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents`

Future project bootstrap work must copy from this path by default. Do not hardcode any other competing `.agents` template path.

## Copy Rules

- Copy the complete `.agents` directory into the target project root.
- Preserve internal paths, names, references, scripts, and skill folders.
- Do not fork or partially copy the structure unless the user explicitly requests a partial copy.
- Do not rename skills during bootstrap.
- Do not create a second `AGENTS.md`.
- Keep the copied `AGENTS.md` and `skills` structure in sync by using the master copy as the template.

## Destination Rules

- Respect existing files in the destination repo.
- If `<TargetRepoPath>\.agents` already exists, do not overwrite it by default.
- If overwrite is requested, prefer a merge that updates files without deleting destination-only files unless the user explicitly asks to replace the folder.
- Report skipped files and validation results.
- Keep starter folders generic unless the project type is clear.

## Validation Rules

After copying, verify:

- `<TargetRepoPath>\.agents\AGENTS.md`
- `<TargetRepoPath>\.agents\skills\`

If either is missing, treat the bootstrap as incomplete and repair the copy before continuing.
