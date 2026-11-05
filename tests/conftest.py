# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Shared fixture running action.yaml's install step against stubs.

The step's script is read out of ``action.yaml`` rather than copied
here, so the tests cannot drift from the implementation they cover.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_STEP = "Install build products/dependencies"

# Records the program path, then each argument on its own line, so a
# path containing a space can be told apart from two arguments. Asked
# to create a virtual environment, it copies itself in as that
# environment's interpreter, so later calls through it are logged too.
STUB = """#!/usr/bin/env bash
{
  printf 'prog=%s\\n' "$0"
  printf 'argc=%s\\n' "$#"
  printf 'arg=%s\\n' "$@"
} >> "$STUB_LOG"
if [ "${1:-}" = '-m' ] && [ "${2:-}" = 'venv' ]; then
  dest="${!#}"
  mkdir -p "$dest/bin"
  cp "$0" "$dest/bin/python"
fi
exit 0
"""


def install_step() -> dict:
    """Return the install step, read from action.yaml."""
    action = yaml.safe_load((REPO_ROOT / "action.yaml").read_text())
    for step in action["runs"]["steps"]:
        if step.get("name") == INSTALL_STEP:
            return step
    raise AssertionError(f"step not found in action.yaml: {INSTALL_STEP}")


class InstallStepRunner:
    """Run the install step with stub pip/python and capture their args.

    Calling an instance gives back the completed process and the stub
    invocation log. Its attributes expose the paths the run used.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.stub_dir = tmp_path / "stub"
        self.stub_dir.mkdir()
        self.runner_temp = tmp_path / "runner-temp"
        self.runner_temp.mkdir()
        self.log = tmp_path / "invocations.log"
        self.log.touch()
        self.env_files = {
            name: tmp_path / name.lower()
            for name in ("GITHUB_OUTPUT", "GITHUB_ENV", "GITHUB_PATH")
        }
        for path in self.env_files.values():
            path.touch()
        for tool in ("pip", "python"):
            stub = self.stub_dir / tool
            stub.write_text(STUB)
            stub.chmod(0o755)
        self.script = tmp_path / "install-step.sh"
        self.script.write_text(install_step()["run"])

    def __call__(
        self, artefact_path: Path
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        env = dict(os.environ)
        env.pop("VIRTUAL_ENV", None)
        env["PATH"] = f"{self.stub_dir}{os.pathsep}{env['PATH']}"
        env["STUB_LOG"] = str(self.log)
        env["RUNNER_TEMP"] = str(self.runner_temp)
        env["INPUT_PATH_PREFIX"] = ""
        env["INPUT_ARTEFACT_PATH"] = str(artefact_path)
        env.update({name: str(path) for name, path in self.env_files.items()})
        proc = subprocess.run(
            ["bash", str(self.script)],
            capture_output=True,
            text=True,
            env=env,
            cwd=self.tmp_path,
            check=False,
        )
        return proc, self.log.read_text()


@pytest.fixture(name="run_install_step")
def _run_install_step(tmp_path: Path) -> InstallStepRunner:
    """Return a runner for the install step, isolated under tmp_path."""
    return InstallStepRunner(tmp_path)
