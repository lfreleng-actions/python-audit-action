# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regression cover for the dependency cache scope (issue #215).

The cache step used to hash dependency files across the whole
workspace (``**/`` globs, ignoring ``path_prefix``) and cached
``.venv``, ``.tox`` and Poetry/Pipenv directories that this action
never creates. Only pip's cache is populated, and the key should track
what the install step consumes: the wheels in ``artefact_path`` and the
optional ``requirements.txt`` in ``path_prefix``.

The step is read out of ``action.yaml`` rather than copied here, so the
tests cannot drift from the implementation.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_ACTION = "actions/cache@"
DOWNLOAD_ACTION = "actions/download-artifact@"
INSTALL_STEP = "Install build products/dependencies"
WHEEL_PATTERN = "format('{0}/*.whl', inputs.artefact_path)"
REQUIREMENTS_PATTERN = "format('{0}/requirements.txt', inputs.path_prefix || '.')"


def _steps() -> list[dict]:
    """Return the composite action's steps, read from action.yaml."""
    action = yaml.safe_load((REPO_ROOT / "action.yaml").read_text())
    return action["runs"]["steps"]


def _index(predicate) -> int:
    """Return the index of the single step matching predicate."""
    matches = [i for i, s in enumerate(_steps()) if predicate(s)]
    assert len(matches) == 1, f"expected one matching step, got {matches}"
    return matches[0]


def _cache_index() -> int:
    return _index(lambda s: str(s.get("uses", "")).startswith(CACHE_ACTION))


def _cache_step() -> dict:
    return _steps()[_cache_index()]


def test_cache_path_is_only_pip_cache():
    """Only ~/.cache/pip is cached; nothing the action never creates."""
    path = str(_cache_step()["with"]["path"]).strip()
    assert path == "~/.cache/pip", path


def test_cache_key_hashes_project_scoped_inputs():
    """The key hashes the wheels and the path_prefix requirements.txt."""
    key = str(_cache_step()["with"]["key"])
    assert WHEEL_PATTERN in key, key
    assert REQUIREMENTS_PATTERN in key, key


def test_cache_key_has_no_workspace_wide_globs():
    """No '**/' glob: unrelated files in the workspace must not churn it."""
    key = str(_cache_step()["with"]["key"])
    assert "**/" not in key, key


def test_artefacts_downloaded_before_cache_key_is_computed():
    """hashFiles() needs the wheels on disk when the cache step runs."""
    downloads = [
        i
        for i, s in enumerate(_steps())
        if str(s.get("uses", "")).startswith(DOWNLOAD_ACTION)
    ]
    assert downloads, "no download step found"
    assert max(downloads) < _cache_index()


def test_cache_restored_before_install():
    """The pip cache is only useful if restored before pip installs."""
    install = _index(lambda s: s.get("name") == INSTALL_STEP)
    assert _cache_index() < install
