<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🐍 Python Dependency Audit

Check a Python project's dependencies for known security vulnerabilities.

## python-audit-action

## Usage Example

<!-- markdownlint-disable MD046 -->

Below is a sample matrix job configuration for this action:

```yaml
  python-audit:
    name: "Python Audit"
    runs-on: "ubuntu-24.04"
    needs:
      - python-build
    # Matrix job
    strategy:
      fail-fast: false
      matrix: ${{ fromJson(needs.python-build.outputs.matrix_json) }}
    permissions:
      contents: read
    steps:
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
```

<!-- markdownlint-enable MD046 -->

Before the audit shown above, a Python build job has run (not shown).

### Multi-Architecture Example

When auditing builds for different architectures, use the `artefact_name` input
to download the correct architecture-specific artefacts:

<!-- markdownlint-disable MD046 -->

```yaml
  python-audit-x64:
    name: "Python Audit x64"
    runs-on: "ubuntu-latest"
    needs: python-build-x64
    strategy:
      fail-fast: false
      matrix: ${{ fromJson(needs.python-build-x64.outputs.matrix_json) }}
    steps:
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          artefact_name: my-package-x64

  python-audit-arm64:
    name: "Python Audit ARM64"
    runs-on: "ubuntu-24.04-arm"
    needs: python-build-arm64
    strategy:
      fail-fast: false
      matrix: ${{ fromJson(needs.python-build-arm64.outputs.matrix_json) }}
    steps:
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          artefact_name: my-package-arm64
```

<!-- markdownlint-enable MD046 -->

## Usage Examples

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
```

### Bypass the default behaviour

To audit all vulnerabilities and bypass default exclusions:

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          ignore_vulns: ""            # Clears the ignore_vulns default
          allow_list_disable: "true"  # Also skip the central allow-list
```

> [!IMPORTANT]
> An empty `ignore_vulns` resets that one input's default, but the
> action still loads the central allow-list automatically (see below).
> To audit **every** vulnerability, also set
> `allow_list_disable: "true"` and do not pass `config` (`config` is
> another allow-list source and is mutually exclusive with
> `allow_list_disable`).

### Ignoring Specific Vulnerabilities

To ignore specific vulnerabilities:

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          ignore_vulns: "GHSA-4xh5-x5gv-qwph CVE-2024-XXXX-YYYY"
```

### Centrally managed allow-list (recommended)

The action can load a vulnerability allow-list from a file hosted in
the organisation's `.github` repository. With no `allow_list_*`
inputs supplied, the action attempts to fetch:

```text
https://raw.githubusercontent.com/<org>/.github/HEAD/.github/python-audit/<org>/allow_list.txt
```

where `<org>` defaults to `github.repository_owner`. IDs from this
file merge with whatever the caller passes in `ignore_vulns` (with
duplicates removed).

This behaviour is automatic: when the default URL returns a 404
(no central file published) the action proceeds with the
`ignore_vulns` input alone, without emitting a warning. An
explicitly-supplied `allow_list_path` or `allow_list_url` that
fails to load is a hard error.

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          # No allow_list_* inputs: defaults to the org's .github file.
```

To load from a local file (highest precedence; overrides URL and org):

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          allow_list_path: ".github/python-audit/${{ github.repository_owner }}/allow_list.txt"
```

To load from an explicit URL:

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          allow_list_url: "https://example.com/python-audit-allow-list.txt"
```

To opt out of allow-list loading entirely:

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          allow_list_disable: "true"
```

#### Allow-list file format

Whitespace-separated vulnerability IDs. `#` introduces a comment
(full-line or trailing). The parser skips blank lines. Each token
must match one of:

- `CVE-YYYY-NNNN[N...]`
- `GHSA-xxxx-xxxx-xxxx` (lowercase alphanumerics)
- `PYSEC-YYYY-N+`
- `OSV-YYYY-N+`
- `PVE-N+` or `PVE-N+-N+` (e.g. `PVE-2021-99`)

Any token that does not match one of these patterns fails the step
rather than passing through unrecognised.

Example file (e.g.
`.github/python-audit/lfreleng-actions/allow_list.txt`):

```text
# lfreleng-actions: globally allow-listed Python audit vulnerabilities

# pip: malicious sdist link traversal (no fix in shipped pip versions)
GHSA-4xh5-x5gv-qwph

# pyjwt: disputed by upstream; key length is the application's
# responsibility, not the library's.
PYSEC-2025-183
```

### Pinned allow-list via `config` (git, SHA-pinnable)

The `config` input is a GitHub-Actions `uses:`-style coordinate that
identifies a remote allow-list file and fetches it with a shallow,
ref-pinned **git** fetch (rather than an unpinned HTTP download). It
supports branches, tags and commit SHAs, so you can pin the
allow-list to an immutable commit, much like an action pin.

> [!IMPORTANT]
> `config` is **mutually exclusive** with the allow-list *source*
> inputs: supplying any of `allow_list_path`, `allow_list_url`,
> `allow_list_org` or `allow_list_disable` together with `config` is
> an error. (`allow_list_summary` still applies, and `ignore_vulns`
> is not a source and still merges with the IDs loaded via `config`.)

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          config: "lfreleng-actions@v1.0.0"
```

#### `config` grammar

```text
<config> ::= <source> [ "@" <ref> ] [ <ws>+ "#" <comment> ]
<source> ::= [ <host-org> [ "/" <repo> ] ] [ "//" <subpath> ]
```

Defaults applied to anything you omit:

<!-- markdownlint-disable MD013 -->

| Element   | Default                                                             |
| --------- | ------------------------------------------------------------------- |
| host-org  | `github.repository_owner` (when you omit the org)                   |
| repo      | `.github`                                                           |
| directory | `.github/python-audit/<workflow-org>/` then `.github/python-audit/` |
| filename  | `allow_list.txt`                                                    |
| ref       | the host repo's default branch (`HEAD`)                             |

<!-- markdownlint-enable MD013 -->

- The `//` separator splits the repository from the in-repo path
  (the same convention Terraform/go-getter use). Text after `//`:
  - **empty** (or no `//`) — default directory search + default
    filename.
  - **bare filename** (no `/`) — overrides the filename, keeps the
    default directory search.
  - **contains a `/`** — an explicit in-repo path; the action skips
    the search and that exact path must exist.
- A `#` preceded by at least one space or tab starts a trailing
  comment; the parser drops everything from that `#` to end of line.
  A `#` with no preceding whitespace forms part of a token
  (so `foo#bar` is a single token, not a comment).
- The output `resolved_sha` always reports the commit the ref
  resolved to, even when you pin a branch or tag.

#### Search / fallback chain

When the directory is auto-derived (you did not give an explicit
directory after `//`), the action tries, in order:

1. `.github/python-audit/<workflow-org>/<filename>` (org-specific)
2. `.github/python-audit/<filename>` (host-wide family default)
3. `.github/python-audit/<org>/<filename>` when a **single** org
   directory in the fetched tree carries the file (sole-org fallback)

The first file that exists wins. The sole-org fallback covers forks:
a fork's `.github` repository carries the upstream org's file at the
pinned ref, but the workflow org resolves to the fork owner, which
prevents the org-specific candidate from matching there. With a
single org directory present the choice is unambiguous and the
ref-pinned content is byte-identical to upstream; two or more org
directories keep the miss (the choice would be ambiguous). Explicit
paths never fall back.

If no candidate exists, the action
proceeds with `ignore_vulns` alone (soft) — consistent with the
default-URL behaviour above. When the sole-org fallback finds the
file under two or more org directories it notes the ambiguity on
stderr, but the miss stays soft in the same way. An **explicit**
path that is missing is always a hard error.

#### `config` examples

Assuming the workflow runs in org `onap`:

<!-- markdownlint-disable MD013 -->

| `config` value                         | Fetched from                    | In-repo path (search chain)                                              |
| -------------------------------------- | ------------------------------- | ------------------------------------------------------------------------ |
| `lfreleng-actions@main`                | `lfreleng-actions/.github@main` | `…/python-audit/onap/allow_list.txt` → `…/python-audit/allow_list.txt`   |
| `lfit@v1.1.0`                          | `lfit/.github@v1.1.0`           | same chain                                                               |
| `lfit@ab7a940… # v1.0.0`               | `lfit/.github@<sha>`            | same chain; comment ignored                                              |
| `lfit//custom_list.txt@v1.1.0  # ONAP` | `lfit/.github@v1.1.0`           | `…/python-audit/onap/custom_list.txt` → `…/python-audit/custom_list.txt` |
| `lfit//@ab7a940…`                      | `lfit/.github@<sha>`            | default chain + `allow_list.txt`                                         |
| `lfit//configs/onap/list.txt@main`     | `lfit/.github@main`             | `configs/onap/list.txt` (explicit; no search)                            |
| `//team_list.txt@main`                 | `onap/.github@main`             | `…/python-audit/onap/team_list.txt` → `…/python-audit/team_list.txt`     |

<!-- markdownlint-enable MD013 -->

#### Private host repositories

For a private host-org `.github` repo, pass a token with
`contents:read` on that repo. `GITHUB_TOKEN` grants access to the
current repository alone, so pass a PAT or GitHub App token here:

```yaml
        with:
          python_version: ${{ matrix.python-version }}
          config: "my-private-org@v2.0.0"
          token: ${{ secrets.CONFIG_READ_TOKEN }}
```

#### `config` outputs

Using `config` makes the action expose: `resolved_host_org`,
`resolved_repo`, `resolved_ref`, `resolved_sha`, `resolved_path` and
`matched_candidate`. Use `resolved_sha` to record or assert which
commit supplied the allow-list.

> [!NOTE]
> `config` resolution uses `python3` from `PATH` (the resolver needs no
> third-party packages) and shells out to `git` for the fetch. It
> runs before the action installs the project under audit, and with
> `python3 -I -S`, so code from the audited project and its
> dependencies never runs alongside `token`. GitHub-hosted runners
> ship both tools; on self-hosted runners `python3` and `git` must sit
> on `PATH`. Both repositories mirror the
> shared parser `src/resolve_config_source.py`, and changes must land
> as paired pull requests across `python-audit-action` and
> `harden-runner-block-action`.

#### Suppressing the step summary on matrix jobs

Each matrix leg is a separate job with its own step summary, so the
allow-list block repeats once per leg. An action cannot detect the
matrix context itself, but the calling workflow can. Set
`allow_list_summary` so a single leg emits the block:

```yaml
        with:
          python_version: ${{ matrix.python-version }}
          # Emit the allow-list summary from the first matrix leg.
          allow_list_summary: ${{ strategy.job-index == 0 }}
```

Outside a matrix, `strategy.job-index` is empty; use
`${{ !strategy.job-total || strategy.job-index == 0 }}` if a single
template must cover both matrix and non-matrix jobs.

## Inputs

<!-- markdownlint-disable MD013 -->

| Variable Name      | Required | Default   | Description                                                                                                                                                                                                                |
| ------------------ | -------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| python_version     | True     | N/A       | Matrix job Python version                                                                                                                                                                                                  |
| artefact_name      | False    |           | Custom name for downloaded artefacts (defaults to project name). Useful when building for different platforms/architectures to avoid artefact name conflicts                                                               |
| permit_fail        | False    | False     | Continue/pass even when the audit fails. Accepts `true` or `false` (any case); any other value, including an empty string, fails the action.                                                                               |
| artefact_path      | False    | "dist"    | Path/location to build artefacts                                                                                                                                                                                           |
| summary            | False    | True      | Whether pypa/gh-action-pip-audit generates summary output                                                                                                                                                                  |
| path_prefix        | False    | ""        | Path/directory to Python project code                                                                                                                                                                                      |
| ignore_vulns       | False    | See below | Vulnerability IDs to ignore (whitespace separated). Merged with allow-list IDs.                                                                                                                                            |
| allow_list_path    | False    |           | Local path to allow-list file. Highest precedence; overrides URL and org.                                                                                                                                                  |
| allow_list_url     | False    |           | Explicit HTTPS URL to fetch the allow-list from. The action ignores this when `allow_list_path` has a value.                                                                                                               |
| allow_list_org     | False    |           | Org used to construct the default allow-list URL. Defaults to `github.repository_owner`.                                                                                                                                   |
| allow_list_disable | False    | False     | Skip allow-list loading entirely.                                                                                                                                                                                          |
| config             | False    | ""        | `uses:`-style coordinate for a git-fetched, SHA-pinnable allow-list. Mutually exclusive with `allow_list_path`/`allow_list_url`/`allow_list_org`/`allow_list_disable` (but `allow_list_summary` still applies). See above. |
| token              | False    | ""        | Token with `contents:read` for fetching a private host repo via `config`. Leave empty for public repos.                                                                                                                    |
| allow_list_summary | False    | True      | Write the allow-list/config block to the job step summary. Set `false` to suppress (e.g. on matrix legs other than the first). See note below.                                                                             |

<!-- markdownlint-enable MD013 -->

## Outputs

<!-- markdownlint-disable MD013 -->

| Variable Name | Description                                                                                                                                                                 |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| audit_outcome | Outcome of the pip-audit step that ran: `success`, `failure` or `cancelled`, or `skipped` when no audit ran. Reports `failure` even when `permit_fail` let the action pass. |

<!-- markdownlint-enable MD013 -->

Using `config` adds further outputs; see [`config` outputs](#config-outputs).

## Audit Implementation

The audit process uses an external public action:

[https://github.com/pypa/gh-action-pip-audit](https://github.com/pypa/gh-action-pip-audit)

## Ignored Vulnerabilities

Security flaws in common Python infrastructure packages can cause widespread
failures of workflows. Specific vulnerabilities get added to the table
below to prevent audits from causing widespread workflow failures/blocking.

<!-- markdownlint-disable MD013 -->

| Package | Version | Vulnerability       | Description                                                                                        |
| ------- | ------- | ------------------- | -------------------------------------------------------------------------------------------------- |
| pip     | 25.2    | GHSA-4xh5-x5gv-qwph | A malicious sdist can include links that escape the target directory and overwrite arbitrary files |

<!-- markdownlint-enable MD013 -->
