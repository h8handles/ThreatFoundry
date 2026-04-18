---
name: mvp-feature-shipper
description: Ship practical application features quickly with small, user-visible improvements across routes, forms, UI wiring, simple data models, and lightweight app flows.
---

# MVP Feature Shipper

## Purpose

Use this skill when the goal is to get a working feature into an application quickly without overbuilding it.  
This skill is optimized for iterative app delivery, especially when the user values practical progress over perfect architecture.

## When To Use

Use this skill for tasks such as:

- adding a page, endpoint, or button
- wiring a form to backend logic
- fixing broken feature flows
- implementing basic CRUD behavior
- improving UI behavior enough to make the app usable
- connecting a simple database-backed feature
- delivering a visible MVP milestone fast

## Working Rules

- Optimize for working software, not theoretical elegance.
- Keep changes tightly scoped and easy to explain.
- Prefer explicit, readable code.
- Preserve existing imports unless removal is necessary.
- Do not redesign the whole app to ship one feature.
- Align frontend actions, backend routes, and data fields carefully.
- Leave the feature in a state that can be extended later.

## Default Workflow

1. Define the exact feature or broken user flow.
2. Identify the route, template, script, or model involved.
3. Implement the smallest complete vertical slice needed.
4. Ensure the user can trigger the feature end to end.
5. Patch obvious validation or UX issues that block use.
6. Summarize what is now working and what is still intentionally simple.

## Common Focus Areas

### App Wiring
- buttons to endpoints
- form actions
- redirect flow
- template rendering
- route-method alignment
- parameter passing

### Light Data Work
- simple model additions
- field alignment
- safe constructor usage
- query and display logic
- basic aggregation for user-facing output

### Practical UX
- clear error handling
- visible success path
- basic page polish
- enough structure for demos, testing, or stakeholder review

## Output Expectations

For each task, prefer to deliver:

- exact feature shipped or repaired
- files changed
- user flow now supported
- any manual setup step if required
- note on what remains intentionally minimal

## Avoid

- large-scale redesigns
- premature abstraction
- heavy frameworks to solve small problems
- polishing unrelated parts of the app during a single feature task
