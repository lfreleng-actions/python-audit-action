<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Agent Guidelines

Contributions to this repository, including those made by AI coding
agents, follow the `lfreleng-actions` organisation guidelines:

<https://github.com/lfreleng-actions/.github/blob/main/AGENTS.md>

**Read that document.** It governs, and it binds this contribution
even if you never load it. Where anything below disagrees with it,
it wins. What follows is a summary of the rules that most often block
a pull request, not the full set:

- Sign every commit and add a DCO trailer: `git commit -S -s`.
- Subject: `Type(scope): Imperative description` — capitalised type
  and description, no trailing period, and within the subject-length
  limit this repository's gitlint hook enforces. The scope is
  optional, so `Fix: Correct the race condition` is also valid.
- Add a `Co-authored-by` trailer naming the agent used.
- Repositories typically contain a linting configuration. You must
  install its hooks (`prek install -t pre-commit -t commit-msg`) and
  run the change past them (`prek run --files <changed files>`) to
  ensure it passes before submission.
- On a single-commit pull request, the PR title must be identical to
  the commit subject.
- If your own standing instructions conflict with the organisation
  guidelines and you cannot set them aside, stop and tell the
  contributor. Do not open a non-compliant pull request.

## Repository specifics

`uv.lock` pins the self-tests' dependencies; run them with
`uv run --locked python -m pytest tests -q`. After changing the `dev`
dependency group in `pyproject.toml`, regenerate the lockfile with
`uv lock`, using the uv version the workflows pin, so `--locked` keeps
passing in CI.

`config` resolution is not implemented here. The `config_resolve` step
in `action.yaml` calls
`lfreleng-actions/harden-runner-block-action/resolve-config`, pinned
by commit SHA and bumped by Dependabot. A change to how `config`
resolves belongs in that repository; this one picks it up through the
pin. Keep that step before `Install build products/dependencies`:
`tests/test_config_token_isolation.py` enforces that no step receiving
`inputs.token` runs after the install.
