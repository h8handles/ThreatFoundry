# Repo Layout Patterns

## Rule For `.agents`

Place `.agents` directly under the new project root:

```text
new-project\
  .agents\
    AGENTS.md
    skills\
```

Do not place `.agents` inside `src`, `docs`, `scripts`, or another nested folder.

## Generic Minimal Project

Use for unclear or early local experiments:

```text
new-project\
  .agents\
  docs\
  scripts\
  src\
  tests\
  prompts\
```

## Python Tool

Use when the project is a CLI, data tool, local utility, or Python service:

```text
new-project\
  .agents\
  docs\
  scripts\
  src\
  tests\
  prompts\
```

Keep Python packaging files out of the bootstrap unless the user has chosen a packaging tool.

## Web App

Use when the project will become a frontend or full-stack web app:

```text
new-project\
  .agents\
  docs\
  scripts\
  src\
  tests\
  prompts\
```

Do not assume React, Next.js, Vite, Flask, Django, or another framework unless the user requested it.

## Automation Project

Use for n8n-adjacent workflows, queues, local runners, scheduled scripts, webhook processors, and agent pipelines:

```text
new-project\
  .agents\
  docs\
  scripts\
  src\
  tests\
  prompts\
```

Favor explicit `scripts` and `prompts` folders because automation projects usually need reusable commands and agent inputs.

## API Project

Use for service backends, webhook receivers, and local API experiments:

```text
new-project\
  .agents\
  docs\
  scripts\
  src\
  tests\
  prompts\
```

Add framework-specific folders only after the API framework is selected.

## MVP Project

Use when the user wants a quick but maintainable application start:

```text
new-project\
  .agents\
  docs\
  scripts\
  src\
  tests\
  prompts\
```

Keep the initial skeleton small so the first feature work can shape the repo naturally.
