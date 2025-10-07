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
    # Matrix job
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
          ignore_vulns: ""  # Empty string clears defaults
```

### Ignoring Specific Vulnerabilities

To ignore specific vulnerabilities:

```yaml
      - name: "Audit project dependencies"
        uses: lfreleng-actions/python-audit-action@main
        with:
          python_version: ${{ matrix.python-version }}
          ignore_vulns: "GHSA-4xh5-x5gv-qwph CVE-2024-XXXX-YYYY"
```

## Inputs

<!-- markdownlint-disable MD013 -->

| Variable Name   | Required | Default   | Description                                                 |
| --------------- | -------- | --------- | ----------------------------------------------------------- |
| python_versions | True     | N/A       | Matrix job Python version                                   |
| permit_fail     | False    | False     | Continue/pass even when the audit fails                     |
| artefact_path   | False    | "dist"    | Stores the test coverage report bundle as an artefact       |
| summary         | False    | True      | Whether pypa/gh-action-pip-audit generates summary output   |
| path_prefix     | False    | ""        | Path/directory to Python project code                       |
| ignore_vulns    | False    | See below | Vulnerability IDs to ignore (whitespace separated)          |

<!-- markdownlint-enable MD013 -->

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
