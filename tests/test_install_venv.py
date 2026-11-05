# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Cover for keeping audited packages out of the job's Python.

The interpreter that actions/setup-python puts on PATH serves every
later step of the calling job. Packages installed into it stay there
after the action finishes, and any ``.pth`` file or ``sitecustomize``
they ship runs in every later Python process. The install step must
therefore install into a virtual environment of the action's own,
leave PATH and VIRTUAL_ENV alone, and hand that environment to both
pip-audit steps.

The install step runs against stub tooling (see ``conftest.py``); the
audit steps are read out of ``action.yaml``.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from conftest import REPO_ROOT, install_step

AUDIT_ACTION = "pypa/gh-action-pip-audit@"
VENV_SUBPATH = Path("python-audit-action") / "venv"


def _invocations(log: str) -> list[tuple[str, list[str]]]:
    """Split the stub log into (program, arguments) pairs."""
    calls: list[tuple[str, list[str]]] = []
    for line in log.splitlines():
        key, _, value = line.partition("=")
        if key == "prog":
            calls.append((value, []))
        elif key == "arg":
            calls[-1][1].append(value)
    return calls


def _wheel_dir(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "pkg-1.0-py3-none-any.whl").touch()
    return dist


def test_venv_created_from_job_python(run_install_step, tmp_path):
    """The job's python only creates the venv, cleared of earlier runs."""
    proc, log = run_install_step(_wheel_dir(tmp_path))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    venv = run_install_step.runner_temp / VENV_SUBPATH
    path_tools = {str(run_install_step.stub_dir / t) for t in ("pip", "python")}
    calls = [args for prog, args in _invocations(log) if prog in path_tools]
    assert calls == [["-m", "venv", "--clear", str(venv)]], calls


def test_every_install_runs_in_the_venv(run_install_step, tmp_path):
    """Wheels and tooling install through the venv's own interpreter."""
    dist = _wheel_dir(tmp_path)
    req = tmp_path / "requirements.txt"
    req.write_text("example==1.0\n")

    proc, log = run_install_step(dist)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    venv_python = str(run_install_step.runner_temp / VENV_SUBPATH / "bin" / "python")
    installs = [(p, a) for p, a in _invocations(log) if "install" in a]
    assert installs, log
    assert all(p == venv_python for p, _ in installs), installs
    installed = [arg for _, args in installs for arg in args]
    assert str(dist / "pkg-1.0-py3-none-any.whl") in installed, installs
    assert "requirements.txt" in installed, installs


def test_venv_path_is_a_step_output(run_install_step, tmp_path):
    """The step reports the venv so the audit steps can use it."""
    proc, _ = run_install_step(_wheel_dir(tmp_path))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    venv = run_install_step.runner_temp / VENV_SUBPATH
    output = run_install_step.env_files["GITHUB_OUTPUT"].read_text()
    assert output.splitlines() == [f"venv={venv}"], output


def test_job_environment_left_alone(run_install_step, tmp_path):
    """Nothing is added to PATH or the environment of later steps."""
    proc, _ = run_install_step(_wheel_dir(tmp_path))

    assert proc.returncode == 0, proc.stdout + proc.stderr
    for name in ("GITHUB_ENV", "GITHUB_PATH"):
        content = run_install_step.env_files[name].read_text()
        assert content == "", f"{name}: {content!r}"


def test_audit_steps_use_the_install_venv():
    """Both pip-audit steps audit the venv the install step built."""
    step_id = install_step().get("id")
    assert step_id, "install step needs an id to expose its output"
    action = yaml.safe_load((REPO_ROOT / "action.yaml").read_text())
    audits = [
        s
        for s in action["runs"]["steps"]
        if str(s.get("uses", "")).startswith(AUDIT_ACTION)
    ]
    assert len(audits) == 2, audits
    expected = f"${{{{ steps.{step_id}.outputs.venv }}}}"
    for step in audits:
        assert step["with"].get("virtual-environment") == expected, step
