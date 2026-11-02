# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Regression cover for keeping the config token away from the audit.

The install step puts the project under audit, and everything it pulls
in, into the setup-python interpreter. A wheel can drop a ``.pth`` file
into site-packages, and Python runs its ``import`` lines at start-up,
so any later step that runs that interpreter with ``inputs.token`` in
its environment hands the token to the audited project's code.

These tests pin that no step that receives the token runs after the
install step, and that the config step calls harden-runner-block-action's
``resolve-config`` sub-action pinned by commit SHA.

The tests that ran the config step's script against a hostile ``.pth``
moved to harden-runner-block-action with the resolver: this action no
longer carries that script, only a ``uses:`` reference to the
sub-action, which runs the resolver with ``python3 -I -S``.

Steps are read out of ``action.yaml`` rather than copied here, so the
tests cannot drift from the implementation they cover.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALL_STEP = "Install build products/dependencies"
CONFIG_STEP_ID = "config_resolve"
TOKEN_REF = "inputs.token"
RESOLVER_USES = re.compile(
    r"lfreleng-actions/harden-runner-block-action/resolve-config@[0-9a-f]{40}"
)


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


def test_token_steps_run_before_install():
    """Every step that receives the token runs before anything is installed."""
    install = _index(lambda s: s.get("name") == INSTALL_STEP)
    token_steps = [i for i, s in enumerate(_steps()) if TOKEN_REF in yaml.safe_dump(s)]
    assert token_steps, f"no step references {TOKEN_REF}"
    late = [i for i in token_steps if i > install]
    assert not late, f"steps {late} receive the token after the install"


def test_config_step_uses_pinned_sub_action():
    """The config step calls the resolve-config sub-action by commit SHA."""
    uses = _config_step().get("uses", "")
    assert RESOLVER_USES.fullmatch(uses), f"unexpected config step uses: {uses!r}"
