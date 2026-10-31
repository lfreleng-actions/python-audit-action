# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regression cover for keeping the config token away from the audit.

The install step puts the project under audit, and everything it pulls
in, into the setup-python interpreter. A wheel can drop a ``.pth`` file
into site-packages, and Python runs its ``import`` lines at start-up,
so any later step that runs that interpreter with ``inputs.token`` in
its environment hands the token to the audited project's code.

These tests pin both halves of the fix: no step that receives the
token runs after the install step, and the config step's interpreter
skips site-packages even when a hostile ``.pth`` is already there (as
on a self-hosted runner whose tool cache persists between jobs).

Steps are read out of ``action.yaml`` rather than copied here, so the
tests cannot drift from the implementation they cover.
"""

from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_STEP = "Install build products/dependencies"
CONFIG_STEP_ID = "config_resolve"
TOKEN_REF = "inputs.token"
TOKEN_VALUE = "ghs_not_a_real_token"

# Fails every call, so the helper stops at its first git command and
# the test needs no network access.
GIT_STUB = """#!/usr/bin/env bash
exit 1
"""


def _steps() -> list[dict]:
    """Return the composite action's steps, read from action.yaml."""
    action = yaml.safe_load((REPO_ROOT / "action.yaml").read_text())
    return action["runs"]["steps"]


def _index(predicate) -> int:
    """Return the index of the single step matching predicate."""
    matches = [i for i, s in enumerate(_steps()) if predicate(s)]
    assert len(matches) == 1, f"expected one matching step, got {matches}"
    return matches[0]


def _config_step() -> dict:
    return _steps()[_index(lambda s: s.get("id") == CONFIG_STEP_ID)]


@pytest.mark.xfail(strict=True, reason="config step runs after install")
def test_token_steps_run_before_install():
    """Every step that receives the token runs before anything is installed."""
    install = _index(lambda s: s.get("name") == INSTALL_STEP)
    token_steps = [i for i, s in enumerate(_steps()) if TOKEN_REF in yaml.safe_dump(s)]
    assert token_steps, f"no step references {TOKEN_REF}"
    late = [i for i in token_steps if i > install]
    assert not late, f"steps {late} receive the token after the install"


def _build_marker_wheel(dist: Path, marker: Path) -> Path:
    """Write a wheel whose .pth copies the TOKEN variable to marker."""
    wheel = dist / "markerpkg-1.0-py3-none-any.whl"
    info = "markerpkg-1.0.dist-info"
    pth = f"import os; open({str(marker)!r}, 'w').write(os.environ.get('TOKEN', ''))\n"
    files = {
        "markerpkg.pth": pth,
        f"{info}/METADATA": "Metadata-Version: 2.1\nName: markerpkg\nVersion: 1.0\n",
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record = "".join(f"{name},,\n" for name in files) + f"{info}/RECORD,,\n"
    with zipfile.ZipFile(wheel, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
        zf.writestr(f"{info}/RECORD", record)
    return wheel


@pytest.fixture(name="hostile_env")
def _hostile_env(tmp_path):
    """Return a PATH whose python3 has a marker-writing .pth installed."""
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    bindir = venv / ("Scripts" if os.name == "nt" else "bin")
    dist = tmp_path / "dist"
    dist.mkdir()
    marker = tmp_path / "marker"
    wheel = _build_marker_wheel(dist, marker)
    subprocess.run(
        [
            str(bindir / "python"),
            "-m",
            "pip",
            "install",
            "-q",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            str(wheel),
        ],
        check=True,
    )
    purelib = sysconfig.get_path(
        "purelib", vars={"base": str(venv), "platbase": str(venv)}
    )
    assert (Path(purelib) / "markerpkg.pth").is_file(), "wheel did not install its .pth"

    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    git = stub_dir / "git"
    git.write_text(GIT_STUB)
    git.chmod(0o755)

    path = os.pathsep.join([str(bindir), str(stub_dir), os.environ["PATH"]])
    return path, marker


def test_marker_wheel_fires_under_plain_python3(hostile_env):
    """Control: the .pth runs, and sees the token, without the fix's flags."""
    path, marker = hostile_env
    env = dict(os.environ, PATH=path, TOKEN=TOKEN_VALUE)
    subprocess.run(["python3", "-c", "pass"], env=env, check=True)
    assert marker.read_text() == TOKEN_VALUE


@pytest.mark.xfail(strict=True, reason="config step loads site-packages")
def test_config_step_does_not_load_site_packages(hostile_env, tmp_path):
    """The config step's python3 never runs the audited environment's .pth."""
    path, marker = hostile_env
    step = _config_step()
    script = tmp_path / "config-step.sh"
    script.write_text(step["run"])

    output = tmp_path / "github_output"
    summary = tmp_path / "step_summary"
    output.touch()
    summary.touch()
    env = dict(os.environ)
    env.update(dict.fromkeys(step["env"], ""))
    env.update(
        {
            "PATH": path,
            "CONFIG": "lfreleng-actions@v1.0.0",
            "TOKEN": TOKEN_VALUE,
            "REPO_OWNER": "lfreleng-actions",
            "ALLOW_LIST_SUMMARY": "true",
            "ACTION_PATH": str(REPO_ROOT),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
        }
    )
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=False,
    )

    # The git stub makes the helper fail at its first fetch; reaching it
    # proves the step got as far as running python3.
    assert proc.returncode != 0
    assert "git init failed" in proc.stderr, proc.stderr
    assert not marker.exists(), "the audited environment's .pth ran with the token"
