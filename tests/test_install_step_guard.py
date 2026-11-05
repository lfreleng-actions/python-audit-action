# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regression cover for the wheel-discovery guard in action.yaml.

The end-to-end workflow job cannot distinguish the guard from the
behaviour it replaced. Without the guard, bash leaves the unmatched
pattern intact, pip is handed the literal string ``dist/*.whl``,
fails, and the action fails anyway, producing the same outcome.

These tests close that gap by running the install step's own script
against stub tooling, so the guard is the only thing that can reject
an empty artefact directory.

The ``run_install_step`` fixture in ``conftest.py`` reads the script
out of ``action.yaml`` rather than copying it here, so the tests cannot
drift from the implementation they cover.
"""

from __future__ import annotations


def test_empty_directory_rejected_by_guard(run_install_step, tmp_path):
    """An empty artefact directory fails, and fails before pip runs."""
    empty = tmp_path / "dist"
    empty.mkdir()

    proc, invocations = run_install_step(empty)

    assert proc.returncode != 0, "an empty artefact directory must fail"
    assert "no wheels found" in proc.stdout, proc.stdout
    # Without the guard the unmatched pattern reaches pip verbatim.
    # That is the behaviour this change exists to remove, so its
    # absence is what proves the guard is present.
    assert "*.whl" not in invocations, invocations


def test_missing_directory_rejected_by_guard(run_install_step, tmp_path):
    """A directory that does not exist fails the same way."""
    proc, invocations = run_install_step(tmp_path / "absent")

    assert proc.returncode != 0, "a missing artefact directory must fail"
    assert "no wheels found" in proc.stdout, proc.stdout
    assert "*.whl" not in invocations, invocations


def test_wheels_in_subdirectories_are_not_found(run_install_step, tmp_path):
    """Wheels one level down do not count, reproducing the regression.

    This is the shape the artefact-name defect produced: download-artifact
    unpacked each artefact into its own subdirectory, so the top-level
    pattern matched nothing.
    """
    dist = tmp_path / "dist"
    (dist / "inner").mkdir(parents=True)
    (dist / "inner" / "pkg-1.0-py3-none-any.whl").touch()

    proc, invocations = run_install_step(dist)

    assert proc.returncode != 0, "wheels in subdirectories must not count"
    assert "no wheels found" in proc.stdout, proc.stdout
    assert "*.whl" not in invocations, invocations


def test_each_wheel_is_installed_as_one_argument(run_install_step, tmp_path):
    """Every wheel installs, including a filename containing a space.

    The previous loop held this property too: pathname expansion runs
    after word splitting, so glob results are never re-split, and
    ``"$wheel"`` was quoted. This does not distinguish the two
    implementations; it pins a property neither should lose.
    """
    dist = tmp_path / "dist"
    dist.mkdir()
    plain = dist / "pkg-1.0-py3-none-any.whl"
    spaced = dist / "other pkg-2.0-py3-none-any.whl"
    plain.touch()
    spaced.touch()

    proc, invocations = run_install_step(dist)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"arg={plain}" in invocations, invocations
    assert f"arg={spaced}" in invocations, invocations
