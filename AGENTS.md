# AGENTS.md

## 1. Project overview

This repository is a menu-driven Python pentest platform for Kali-style workflows.
It is designed for step-by-step operator control, not as a one-button scanner.

The current workflow is centered around selecting a project, managing scope, running recon/web/reporting modules from menus, and saving artifacts into the active project directory.

Keep the existing UX style:
- console menus with `rich`
- explicit operator choices
- practical artifact files under the current project

Do not invent a new architecture when working in this repo. Extend the current project structure and current menu flow unless the user explicitly asks for a redesign.

## 2. Directory structure

### `core/`
Shared platform logic and project state.

Current responsibilities include:
- main menu entrypoint
- project create/open flow
- active project context via `project_context`
- config load/save helpers
- scope management
- generic utility helpers such as `require_project()`

### `modules/`
Feature modules grouped by area.

Current groups include:
- `modules/recon/`
- `modules/web/`
- `modules/osint/`
- `modules/phishing/`
- `modules/reports/`

Each module should follow the existing menu-driven style and write its own artifacts into the active project path.

### `reports/`
In this repository, reports functionality lives in `modules/reports/`.

Report artifacts are currently written under the active project, for example:
- `projects/<project_name>/reports/subdomains/...`

### `projects/<project_name>/`
Per-project working directory created by the platform.

Artifacts must be saved inside `projects/<project_name>/...`, not at repo root.

Current project layout includes:
- `config.yaml`
- `recon/`
- `web/`
- `osint/`
- `phishing/`
- `reports/`
- `logs/`

Common current artifact locations include:
- `projects/<project_name>/recon/subdomains/`
- `projects/<project_name>/recon/urls/`
- `projects/<project_name>/recon/nmap/`
- `projects/<project_name>/reports/subdomains/`

## 3. Coding rules

- Follow existing patterns before introducing new ones.
- Prefer minimal local changes over broad refactors.
- Reuse existing helpers from `core/` where possible.
- Keep using `project_context` as the active project state source.
- Preserve current artifact-saving behavior and file placement.
- Do not redesign menus or CLI flow unless explicitly requested.
- Keep code readable and practical; avoid overengineering.
- When adding a module, fit it into the existing menu and artifact layout instead of creating parallel flows.

## 4. Python rules

- Prefer small functions with clear responsibilities.
- Use explicit error handling around filesystem, network, and subprocess operations.
- Use type hints where reasonable, especially for new or edited functions.
- Avoid unnecessary abstractions, deep class hierarchies, or framework-style rewrites.
- Keep comments only where the logic is not obvious.
- Prefer straightforward data structures and file-based artifacts consistent with the current codebase.

## 5. Testing rules

- Before finishing a task, run the smallest relevant checks.
- If logic changes, add or update focused tests when appropriate.
- For script-style modules, prefer targeted validation such as `python3 -m py_compile` or the smallest realistic command path.
- Always report what was run and what the result was.
- If something could not be validated, say so clearly.

## 6. Security rules

- Never hardcode secrets.
- Prefer environment variables or existing config helpers for tokens and credentials.
- Be careful with `subprocess` usage.
- Avoid shell injection risks when building external commands.
- Watch for path traversal when writing artifacts.
- Watch for SSRF when fetching remote resources.
- Use safe temporary-file handling.
- Avoid unsafe deserialization.
- Do not leak secrets into logs, reports, console output, or committed files.

## 7. Output expectations for future tasks

- Summarize changed files.
- Explain why each change was made.
- Report validation commands and results.
- Mention remaining risks, assumptions, or manual checks if needed.
- Keep explanations concise and practical.

## 8. Project-specific notes

- Preserve current menu behavior.
- Preserve current project selection flow from `Project management`.
- Preserve current artifact-saving logic under the active project directory.
- Respect the current use of `config.yaml` as dynamic project state.
- Follow existing naming and file placement patterns.
- Keep the platform step-by-step and operator-driven.
- Do not turn current menus into a fully automatic pipeline unless explicitly requested.
- talk and explain everything to the user only in Russian.