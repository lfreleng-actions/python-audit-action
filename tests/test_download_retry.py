# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regression cover for the artefact download retry (issue #295).

GitHub's artefact service can fail to list an artefact for a few
seconds after its upload, so a download in the job that uploaded it
can miss although the artefact exists. The action repeats the
download step behind ``continue-on-error`` and a check on the previous
attempt's outcome, with a wait step between attempts.

A miss followed by a find cannot be staged on demand, so these tests
read the steps out of ``action.yaml`` and check how they are chained:
each later attempt runs only after a failed one, a wait lies between
attempts, the last failure fails the action, and no later step can run
once every attempt has failed.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DOWNLOAD_ACTION = "actions/download-artifact@"
REPORT_STEP = "Report artefact download failure"
MAX_ATTEMPTS = 5
DELAYS = [2, 4, 8, 16]
NAME_EXPR = "${{ inputs.artefact_name || steps.naming.outputs.project_name }}"
STATUS_FUNCTION = re.compile(r"\b(always|failure|cancelled)\s*\(")


def _steps() -> list[dict]:
    """Return the composite action's steps, read from action.yaml."""
    action = yaml.safe_load((REPO_ROOT / "action.yaml").read_text())
    return action["runs"]["steps"]


def _download_indices() -> list[int]:
    """Return the indices of the download attempts, in order."""
    return [
        i
        for i, s in enumerate(_steps())
        if str(s.get("uses", "")).startswith(DOWNLOAD_ACTION)
    ]


def _after_failure_of(attempt: int) -> str:
    """Return the condition gating the step that follows attempt."""
    return f"${{{{ steps.download_{attempt}.outcome == 'failure' }}}}"


def _run_script(
    step: dict, tmp_path: Path
) -> tuple[subprocess.CompletedProcess[str], str]:
    """Run a step's script with its env and a stub sleep that logs."""
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    log = tmp_path / "sleep.log"
    log.touch()
    stub = stub_dir / "sleep"
    stub.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$@" >> "$SLEEP_LOG"\n')
    stub.chmod(0o755)
    env = dict(os.environ)
    env.update({k: str(v) for k, v in step.get("env", {}).items()})
    env["ARTEFACT_NAME"] = "my-artefact"
    env["SLEEP_LOG"] = str(log)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env['PATH']}"
    proc = subprocess.run(
        ["bash", "-c", step["run"]],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return proc, log.read_text()


@pytest.mark.xfail(strict=True, reason="download retry not yet added")
def test_download_has_fixed_number_of_attempts():
    """Five attempts, each with its own id and the same pin and inputs."""
    steps = _steps()
    attempts = [steps[i] for i in _download_indices()]
    assert len(attempts) == MAX_ATTEMPTS, attempts
    assert [s.get("id") for s in attempts] == [
        f"download_{n}" for n in range(1, MAX_ATTEMPTS + 1)
    ]
    assert len({s["uses"] for s in attempts}) == 1
    for step in attempts:
        assert " ".join(step["with"]["name"].split()) == NAME_EXPR
        assert step["with"]["path"] == "${{ inputs.artefact_path }}"


def test_first_attempt_runs_unconditionally():
    """A download that succeeds at once needs no condition and no wait."""
    first = _steps()[_download_indices()[0]]
    assert "if" not in first, first


def test_each_later_attempt_runs_only_after_a_failure():
    """Attempt n runs only when attempt n - 1 failed."""
    steps = _steps()
    for n, i in enumerate(_download_indices()[1:], start=2):
        assert steps[i].get("if") == _after_failure_of(n - 1), steps[i]


def test_only_the_last_attempt_fails_the_action():
    """Earlier misses are tolerated; the last failure is not swallowed."""
    steps = _steps()
    indices = _download_indices()
    for i in indices[:-1]:
        assert steps[i].get("continue-on-error") is True, steps[i]
    assert "continue-on-error" not in steps[indices[-1]], steps[indices[-1]]


@pytest.mark.xfail(strict=True, reason="download retry not yet added")
def test_a_wait_lies_between_attempts(tmp_path):
    """One wait step between each pair of attempts, gated and sleeping."""
    steps = _steps()
    indices = _download_indices()
    slept = []
    for n, (before, after) in enumerate(zip(indices, indices[1:]), start=1):
        between = steps[before + 1 : after]
        assert len(between) == 1, between
        wait = between[0]
        assert wait.get("if") == _after_failure_of(n), wait
        assert "continue-on-error" not in wait, wait
        assert wait["env"]["ARTEFACT_NAME"] == NAME_EXPR
        run_dir = tmp_path / str(n)
        run_dir.mkdir()
        proc, log = _run_script(wait, run_dir)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert f"attempt {n} of {MAX_ATTEMPTS}" in proc.stdout, proc.stdout
        assert "my-artefact" in proc.stdout, proc.stdout
        slept.append(int(log.strip()))
    assert slept == DELAYS, slept


@pytest.mark.xfail(strict=True, reason="download retry not yet added")
def test_final_failure_names_artefact_and_attempts(tmp_path):
    """After the last miss, the action says what and how often it tried."""
    steps = _steps()
    report_index = _download_indices()[-1] + 1
    report = steps[report_index]
    assert report.get("name") == REPORT_STEP, report
    assert report.get("if") == (
        f"${{{{ failure() && steps.download_{MAX_ATTEMPTS}.outcome == 'failure' }}}}"
    ), report
    assert report["env"]["ARTEFACT_NAME"] == NAME_EXPR
    proc, _ = _run_script(report, tmp_path)
    assert proc.returncode != 0, proc.stdout
    assert (
        f"::error::Artefact my-artefact not downloaded after {MAX_ATTEMPTS} attempts"
        in proc.stdout
    ), proc.stdout


def test_no_later_step_runs_after_every_attempt_failed():
    """Steps after the download run on success() alone, so are skipped.

    Wheels already in artefact_path must never be audited in place of
    the artefact, so no step after the report may override the implicit
    success() check with a status function.
    """
    steps = _steps()
    report_index = _download_indices()[-1] + 1
    late = [
        s.get("name")
        for s in steps[report_index + 1 :]
        if STATUS_FUNCTION.search(str(s.get("if", "")))
    ]
    assert not late, late


def test_retry_steps_use_no_status_function():
    """Waits and retries are gated on outcome alone, never on always()."""
    steps = _steps()
    indices = _download_indices()
    for step in steps[indices[0] : indices[-1] + 1]:
        assert not STATUS_FUNCTION.search(str(step.get("if", ""))), step
