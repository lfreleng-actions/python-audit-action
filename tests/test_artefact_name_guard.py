# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regression cover for the artefact name guard (issue #282).

build-metadata-action succeeds with an empty ``project_name`` when the
directory holds no project it can name, and download-artifact given an
empty name downloads every artefact in the run. The guard step stops
the action before the download when neither ``artefact_name`` nor the
resolved project name is set.

The workflow test cannot tell this guard from an earlier failure, or
from a download that found nothing to fetch, so these tests run the
guard's script, read out of ``action.yaml``, and check where it sits.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
NAMING_STEP_ID = "naming"
GUARD_STEP = "Check artefact name"
DOWNLOAD_ACTION = "actions/download-artifact@"


def _steps() -> list[dict]:
    """Return the composite action's steps, read from action.yaml."""
    action = yaml.safe_load((REPO_ROOT / "action.yaml").read_text())
    return action["runs"]["steps"]


def _index(match) -> int:
    """Return the index of the single step satisfying match."""
    found = [i for i, s in enumerate(_steps()) if match(s)]
    assert len(found) == 1, found
    return found[0]


def _download_indices() -> list[int]:
    """Return the indices of the download attempts, in order."""
    found = [
        i
        for i, s in enumerate(_steps())
        if str(s.get("uses", "")).startswith(DOWNLOAD_ACTION)
    ]
    assert found, "no download step found"
    return found


def _guard_step() -> dict:
    """Return the guard step, read from action.yaml."""
    return _steps()[_index(lambda s: s.get("name") == GUARD_STEP)]


def _run_guard(
    artefact_name: str, project_name: str
) -> subprocess.CompletedProcess[str]:
    """Run the guard step's script with both names in its environment."""
    env = dict(os.environ)
    env["ARTEFACT_NAME"] = artefact_name
    env["PROJECT_NAME"] = project_name
    return subprocess.run(
        ["bash", "-c", _guard_step()["run"]],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_both_names_empty_fails():
    """With no name to download under, the guard stops the action."""
    proc = _run_guard("", "")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "::error::No artefact name" in proc.stdout, proc.stdout


@pytest.mark.parametrize(
    ("artefact_name", "project_name"),
    [
        ("custom-name", ""),
        ("", "project-name"),
        ("custom-name", "project-name"),
    ],
)
def test_either_name_passes(artefact_name, project_name):
    """Either name is enough to download under."""
    proc = _run_guard(artefact_name, project_name)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "::error::" not in proc.stdout, proc.stdout


def test_guard_reads_the_names_the_download_uses():
    """The guard checks the same two values the download falls back on."""
    assert _guard_step()["env"] == {
        "ARTEFACT_NAME": "${{ inputs.artefact_name }}",
        "PROJECT_NAME": "${{ steps.naming.outputs.project_name }}",
    }
    for i in _download_indices():
        name = " ".join(_steps()[i]["with"]["name"].split())
        assert name == (
            "${{ inputs.artefact_name || steps.naming.outputs.project_name }}"
        ), name


def test_guard_runs_after_naming_and_before_download():
    """The guard sees the resolved name and stops before any download."""
    naming = _index(lambda s: s.get("id") == NAMING_STEP_ID)
    guard = _index(lambda s: s.get("name") == GUARD_STEP)
    download = _download_indices()[0]
    assert naming < guard < download, (naming, guard, download)
    assert "if" not in _guard_step(), "the guard must run unconditionally"
