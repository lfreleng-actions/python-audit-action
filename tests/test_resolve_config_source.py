# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║  SYNCHRONISED FILE — DO NOT EDIT IN ISOLATION                      ║
# ║                                                                    ║
# ║  Mirrored across:                                                  ║
# ║    - lfreleng-actions/python-audit-action       : tests/...        ║
# ║    - lfreleng-actions/harden-runner-block-action: tests/...        ║
# ║                                                                    ║
# ║  These tests pin the shared `config` grammar. Changes must land    ║
# ║  as paired PRs in both repositories together with the module.      ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Unit tests for resolve_config_source: parsing, resolution defaults,
# the search-candidate chain, the mode-selected sanitisers, and
# fetch_file() (with git interactions stubbed via _run_git, so the
# tests never touch the network). The resolver-tests.yaml workflow runs
# this file.

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import resolve_config_source as rcs  # noqa: E402


# ---------------------------------------------------------------------
# Comment splitting
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected_spec,expected_comment",
    [
        ("lfit@v1.1.0", "lfit@v1.1.0", ""),
        ("lfit@v1.1.0 # hello", "lfit@v1.1.0", "hello"),
        ("lfit@v1.1.0  # two spaces", "lfit@v1.1.0", "two spaces"),
        ("lfit@v1.1.0\t# tab", "lfit@v1.1.0", "tab"),
        ("lfit//f.txt@v1 # many words here", "lfit//f.txt@v1", "many words here"),
    ],
)
def test_split_comment(value, expected_spec, expected_comment):
    spec, comment = rcs.split_comment(value)
    assert spec == expected_spec
    assert comment == expected_comment


# ---------------------------------------------------------------------
# Resolution + search candidates
# ---------------------------------------------------------------------


def _resolve(spec, org="onap", family="python-audit"):
    return rcs.resolve(spec, workflow_org=org, family=family)


def test_org_only_default_branch():
    r = _resolve("lfreleng-actions@main")
    assert r["host_org"] == "lfreleng-actions"
    assert r["repo"] == ".github"
    assert r["ref"] == "main"
    assert r["candidates"] == [
        ".github/python-audit/onap/allow_list.txt",
        ".github/python-audit/allow_list.txt",
    ]
    assert r["path_explicit"] is False


def test_no_ref_defaults_to_head():
    r = _resolve("lfit")
    assert r["ref"] == "HEAD"


def test_sha_ref_with_comment():
    r = _resolve("lfit@ab7a9404c0f3da075243ca237b5fac12c98deaa5 # v1.0.0")
    assert r["host_org"] == "lfit"
    assert r["ref"] == "ab7a9404c0f3da075243ca237b5fac12c98deaa5"
    assert r["comment"] == "v1.0.0"


def test_filename_only_keeps_default_dir_search():
    r = _resolve("lfit//custom_list.txt@v1.1.0")
    assert r["candidates"] == [
        ".github/python-audit/onap/custom_list.txt",
        ".github/python-audit/custom_list.txt",
    ]
    assert r["path_explicit"] is False


def test_bare_double_slash_uses_defaults():
    r = _resolve("lfit//@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # note")
    assert r["candidates"] == [
        ".github/python-audit/onap/allow_list.txt",
        ".github/python-audit/allow_list.txt",
    ]
    assert r["ref"] == "ab7a9404c0f3da075243ca237b5fac12c98deaa5"


def test_explicit_directory_disables_search():
    r = _resolve("lfit//configs/onap/list.txt@main")
    assert r["candidates"] == ["configs/onap/list.txt"]
    assert r["path_explicit"] is True


def test_explicit_repo_override():
    r = _resolve("lfit/special-repo//list.txt@main")
    assert r["host_org"] == "lfit"
    assert r["repo"] == "special-repo"


def test_empty_host_org_defaults_to_workflow_org():
    r = _resolve("//team_list.txt@main", org="onap")
    assert r["host_org"] == "onap"
    assert r["candidates"][0] == ".github/python-audit/onap/team_list.txt"


def test_family_appears_in_default_path():
    r = _resolve("lfit@main", family="harden-runner")
    assert r["candidates"] == [
        ".github/harden-runner/onap/allow_list.txt",
        ".github/harden-runner/allow_list.txt",
    ]


# ---------------------------------------------------------------------
# Rejections
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "lfit@",
        "lfit@a@b",
        "lfit//a//b@main",
        "lfit/repo/extra@main",
        "bad org@main",
        "lfit//../escape.txt@main",
        "lfit///abs/path.txt@main",
        "lfit//a\\b.txt@main",
        "lfit@-badref",
        "lfit@ref..with..dots",
        "lfit@ref@{0}",
        "lfit//evil;rm.txt@main",
    ],
)
def test_invalid_specs_raise(spec):
    with pytest.raises(rcs.ResolveError):
        _resolve(spec)


def test_newline_in_config_rejected():
    with pytest.raises(rcs.ResolveError):
        _resolve("lfit@main\nevil")


def test_newline_disguised_as_comment_rejected():
    # A newline before '#' must NOT be treated as a comment separator,
    # otherwise the trailing line would slip past newline rejection.
    with pytest.raises(rcs.ResolveError):
        _resolve("lfit@main\n# hidden")


def test_split_comment_ignores_newline_separator():
    spec, comment = rcs.split_comment("lfit@main\n# hidden")
    assert spec == "lfit@main\n# hidden"
    assert comment == ""


# ---------------------------------------------------------------------
# Sanitisers
# ---------------------------------------------------------------------


def test_sanitise_vulns_accepts_valid_ids():
    raw = (
        "# comment\n"
        "GHSA-4xh5-x5gv-qwph\n"
        "PYSEC-2025-183  # disputed\n"
        "CVE-2024-12345\n"
        "OSV-2023-1 PVE-2021-99\n"
    )
    assert rcs.sanitise(raw, "vulns") == [
        "GHSA-4xh5-x5gv-qwph",
        "PYSEC-2025-183",
        "CVE-2024-12345",
        "OSV-2023-1",
        "PVE-2021-99",
    ]


@pytest.mark.parametrize(
    "token",
    ["evil;rm -rf /", "CVE-2024-1", "GHSA-XXXX-xxxx-xxxx", "not-an-id"],
)
def test_sanitise_vulns_rejects_bad_tokens(token):
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise(token, "vulns")


def test_sanitise_endpoints_accepts_valid():
    raw = "github.com:443 *.githubusercontent.com:443 pypi.org # ok"
    assert rcs.sanitise(raw, "endpoints") == [
        "github.com:443",
        "*.githubusercontent.com:443",
        "pypi.org",
    ]


@pytest.mark.parametrize(
    "token",
    ["evil.com:0", "evil.com:99999", "*", "*:443", "ev|l.com", "a b;c"],
)
def test_sanitise_endpoints_rejects_bad(token):
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise(token, "endpoints")


def test_sanitise_empty_after_comments_raises():
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise("# only a comment\n\n", "vulns")


def test_unknown_mode_raises():
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise("github.com", "bogus")


# ---------------------------------------------------------------------
# fetch_file (git interactions stubbed via _run_git)
# ---------------------------------------------------------------------

import subprocess  # noqa: E402

_FAKE_SHA = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"


def _install_fake_git(
    monkeypatch,
    *,
    fetch_rc=0,
    fetch_errors=None,
    sha=_FAKE_SHA,
    files=None,
    sizes=None,
    trees=None,
):
    """Stub rcs._run_git so fetch_file() runs without touching git/network.

    files maps an in-repo path to its content; sizes optionally overrides
    the reported blob size; trees is a set of paths reported as 'tree'
    objects (directories). fetch_errors lists the stderr of successive
    failing fetches (exit 128); once it runs out, fetches exit with
    fetch_rc. Returns the list of git argument vectors (with the leading
    '-C <tmp>' stripped) for assertions.
    """
    files = files or {}
    sizes = sizes or {}
    trees = set(trees or [])
    fetch_errors = list(fetch_errors or [])
    calls: list[list[str]] = []

    def fake_run_git(args, timeout):
        sub = list(args[2:])  # strip the leading ['-C', tmp]
        calls.append(sub)

        def cp(rc, out="", err=""):
            return subprocess.CompletedProcess(args, rc, out, err)

        if sub[:1] == ["init"]:
            return cp(0)
        if sub[:2] == ["remote", "add"]:
            return cp(0)
        if "fetch" in sub:
            if fetch_errors:
                return cp(128, err=fetch_errors.pop(0))
            return cp(fetch_rc)
        if sub[:1] == ["rev-parse"]:
            return cp(0, sha + "\n")
        if sub[:2] == ["cat-file", "-t"]:
            path = sub[2].split(":", 1)[1]
            if path in trees:
                return cp(0, "tree\n")
            return cp(0, "blob\n") if path in files else cp(1)
        if sub[:2] == ["cat-file", "-s"]:
            path = sub[2].split(":", 1)[1]
            size = sizes.get(path, len(files.get(path, "")))
            return cp(0, f"{size}\n")
        if sub[:1] == ["show"]:
            path = sub[1].split(":", 1)[1]
            return cp(0, files[path])
        if sub[:1] == ["ls-tree"]:
            prefix = sub[-1]
            listed = [
                p for p in sorted(files) if p == prefix or p.startswith(prefix + "/")
            ]
            return cp(0, "".join(f"{p}\n" for p in listed))
        return cp(0)

    monkeypatch.setattr(rcs, "_run_git", fake_run_git)
    return calls


def test_fetch_file_found_first_candidate(monkeypatch):
    cands = [
        ".github/python-audit/onap/allow_list.txt",
        ".github/python-audit/allow_list.txt",
    ]
    _install_fake_git(monkeypatch, files={cands[0]: "CVE-2024-1234\n"})
    result = rcs.fetch_file(
        host_org="lfit",
        repo=".github",
        ref="main",
        candidates=cands,
    )
    assert result["found"] is True
    assert result["matched_path"] == cands[0]
    assert result["resolved_sha"] == _FAKE_SHA
    assert result["content"] == "CVE-2024-1234\n"


def test_fetch_file_falls_back_to_second_candidate(monkeypatch):
    cands = [
        ".github/python-audit/onap/allow_list.txt",
        ".github/python-audit/allow_list.txt",
    ]
    _install_fake_git(monkeypatch, files={cands[1]: "CVE-2024-1234\n"})
    result = rcs.fetch_file(
        host_org="lfit",
        repo=".github",
        ref="main",
        candidates=cands,
    )
    assert result["found"] is True
    assert result["matched_path"] == cands[1]


def test_fetch_file_not_found(monkeypatch):
    cands = ["a/x.txt", "b/x.txt"]
    _install_fake_git(monkeypatch, files={})
    result = rcs.fetch_file(
        host_org="lfit",
        repo=".github",
        ref="main",
        candidates=cands,
    )
    assert result["found"] is False
    assert result["matched_path"] == ""
    assert result["content"] is None
    assert result["resolved_sha"] == _FAKE_SHA


def test_fetch_file_peels_to_commit(monkeypatch):
    cands = ["a/x.txt"]
    calls = _install_fake_git(monkeypatch, files={"a/x.txt": "CVE-2024-1234"})
    rcs.fetch_file(
        host_org="lfit",
        repo=".github",
        ref="v1.0.0",
        candidates=cands,
    )
    assert ["rev-parse", "FETCH_HEAD^{commit}"] in calls


def test_fetch_file_fetch_failure_raises(monkeypatch):
    _install_fake_git(monkeypatch, fetch_rc=1)
    with pytest.raises(rcs.ResolveError):
        rcs.fetch_file(
            host_org="lfit",
            repo=".github",
            ref="main",
            candidates=["a/x.txt"],
        )


_REFUSED_403 = (
    "fatal: unable to access 'https://github.com/lfit/.github.git/': "
    "The requested URL returned error: 403"
)


def _fetch_with_retries(delays):
    """Call fetch_file with a sleep that records each backoff delay."""
    return rcs.fetch_file(
        host_org="lfit",
        repo=".github",
        ref="main",
        candidates=["a/x.txt"],
        sleep=delays.append,
    )


def _fetches(calls):
    return [c for c in calls if "fetch" in c]


def test_fetch_file_retries_refused_fetch(monkeypatch, capsys):
    errors = [_REFUSED_403, _REFUSED_403]
    calls = _install_fake_git(
        monkeypatch, fetch_errors=errors, files={"a/x.txt": "CVE-2024-1234\n"}
    )
    delays: list[float] = []
    result = _fetch_with_retries(delays)
    assert result["found"] is True
    assert len(_fetches(calls)) == 3
    assert delays == [2, 5]
    err = capsys.readouterr().err
    assert "fetch attempt 1 of 3 failed (HTTP 403); retrying in 2 s" in err
    assert "fetch attempt 2 of 3 failed (HTTP 403); retrying in 5 s" in err


def test_fetch_file_refused_every_attempt_raises(monkeypatch):
    errors = [_REFUSED_403] * 3
    calls = _install_fake_git(monkeypatch, fetch_errors=errors)
    delays: list[float] = []
    with pytest.raises(rcs.ResolveError) as exc:
        _fetch_with_retries(delays)
    assert len(_fetches(calls)) == 3
    assert delays == [2, 5]
    message = str(exc.value)
    assert message.startswith("git fetch of 'main' from lfit/.github failed: ")
    assert (
        "GitHub refused the fetch 3 times (HTTP 403); the ref may still "
        "be valid, see the retry log"
    ) in message


def test_fetch_file_unknown_ref_fails_without_retry(monkeypatch):
    errors = ["fatal: couldn't find remote ref main", _REFUSED_403]
    calls = _install_fake_git(monkeypatch, fetch_errors=errors)
    delays: list[float] = []
    with pytest.raises(rcs.ResolveError) as exc:
        _fetch_with_retries(delays)
    assert len(_fetches(calls)) == 1
    assert delays == []
    assert "refused" not in str(exc.value)


def test_fetch_file_retries_stay_inside_timeout(monkeypatch):
    errors = [_REFUSED_403] * 3
    calls = _install_fake_git(monkeypatch, fetch_errors=errors)
    delays: list[float] = []
    with pytest.raises(rcs.ResolveError) as exc:
        rcs.fetch_file(
            host_org="lfit",
            repo=".github",
            ref="main",
            candidates=["a/x.txt"],
            timeout=4,
            sleep=delays.append,
        )
    # The 2 s wait fits a 4 s budget; the 5 s one does not.
    assert len(_fetches(calls)) == 2
    assert delays == [2]
    assert "GitHub refused the fetch 2 times (HTTP 403)" in str(exc.value)


def _install_slow_fetch(monkeypatch, fetch_seconds):
    """Wrap the stubbed _run_git in a fake clock.

    Each fetch advances the clock by fetch_seconds and records the
    timeout it was given. Returns the clock (a one-item list holding
    the current time) and the list of fetch timeouts.
    """
    now = [100.0]
    fetch_timeouts: list[float] = []
    stub = rcs._run_git

    def slow_run_git(args, timeout):
        if "fetch" in args:
            assert timeout > 0
            fetch_timeouts.append(timeout)
            now[0] += fetch_seconds
        return stub(args, timeout)

    monkeypatch.setattr(rcs, "_run_git", slow_run_git)
    return now, fetch_timeouts


def _fetch_on_clock(now, sleep_seconds):
    """Call fetch_file on the fake clock with a 4 s budget.

    Each backoff advances the clock by sleep_seconds when given, or by
    the requested delay otherwise; returns the requested delays.
    """
    delays: list[float] = []

    def fake_sleep(delay):
        delays.append(delay)
        now[0] += delay if sleep_seconds is None else sleep_seconds

    with pytest.raises(rcs.ResolveError) as exc:
        rcs.fetch_file(
            host_org="lfit",
            repo=".github",
            ref="main",
            candidates=["a/x.txt"],
            timeout=4,
            sleep=fake_sleep,
            clock=lambda: now[0],
        )
    return delays, str(exc.value)


def test_fetch_file_retry_gets_only_remaining_time(monkeypatch):
    _install_fake_git(monkeypatch, fetch_errors=[_REFUSED_403] * 3)
    now, fetch_timeouts = _install_slow_fetch(monkeypatch, 1.8)
    delays, message = _fetch_on_clock(now, None)
    # 1.8 s of fetch and a 2 s wait leave 0.2 s of the 4 s budget.
    assert delays == [2]
    assert fetch_timeouts == [4, pytest.approx(0.2)]
    assert "GitHub refused the fetch 2 times (HTTP 403)" in message


def test_fetch_file_no_retry_after_oversleep(monkeypatch):
    calls = _install_fake_git(monkeypatch, fetch_errors=[_REFUSED_403] * 3)
    now, fetch_timeouts = _install_slow_fetch(monkeypatch, 1.8)
    delays, message = _fetch_on_clock(now, 2.5)
    # The 2 s wait overran to 2.5 s, past the deadline: no second fetch.
    assert delays == [2]
    assert fetch_timeouts == [4]
    assert len(_fetches(calls)) == 1
    assert "GitHub refused the fetch once (HTTP 403)" in message


@pytest.mark.parametrize(
    "stderr, expected",
    [
        (_REFUSED_403, "HTTP 403"),
        ("error: RPC failed; HTTP 503 curl 22", "HTTP 503"),
        ("The requested URL returned error: 429", "HTTP 429"),
        ("The requested URL returned error: 408", "HTTP 408"),
        ("fatal: Could not resolve host: github.com", "Could not resolve host"),
        ("fatal: early EOF", "early EOF"),
        ("The requested URL returned error: 404", ""),
        ("The requested URL returned error: 401", ""),
        ("remote: Repository not found.", ""),
        ("fatal: remote error: upload-pack: not our ref deadbeef", ""),
        ("fatal: something unexpected", ""),
    ],
)
def test_transient_fetch_failure_classification(stderr, expected):
    assert rcs._transient_fetch_failure(stderr) == expected


def test_fetch_file_size_limit_raises(monkeypatch):
    cands = ["a/x.txt"]
    _install_fake_git(
        monkeypatch,
        files={"a/x.txt": "x"},
        sizes={"a/x.txt": rcs.MAX_FILE_BYTES + 1},
    )
    with pytest.raises(rcs.ResolveError):
        rcs.fetch_file(
            host_org="lfit",
            repo=".github",
            ref="main",
            candidates=cands,
        )


def test_fetch_file_skips_directory_candidate(monkeypatch):
    # A candidate that resolves to a tree (directory) must not be read
    # as content; the fall-through candidate (a blob) is used instead.
    cands = ["a/dir", "b/x.txt"]
    _install_fake_git(
        monkeypatch,
        files={"b/x.txt": "CVE-2024-1234\n"},
        trees=["a/dir"],
    )
    result = rcs.fetch_file(
        host_org="lfit",
        repo=".github",
        ref="main",
        candidates=cands,
    )
    assert result["found"] is True
    assert result["matched_path"] == "b/x.txt"


def test_fetch_file_directory_only_not_found(monkeypatch):
    # When the only candidate is a directory, nothing is read.
    cands = ["a/dir"]
    _install_fake_git(monkeypatch, trees=["a/dir"])
    result = rcs.fetch_file(
        host_org="lfit",
        repo=".github",
        ref="main",
        candidates=cands,
    )
    assert result["found"] is False


# ---------------------------------------------------------------------
# fetch_file: sole-org fallback (fork scenario)
# ---------------------------------------------------------------------


def test_fetch_file_sole_org_fallback(monkeypatch):
    # Fork scenario: the workflow org derives fork-specific candidates,
    # but the fetched tree carries exactly one (upstream) org's file.
    cands = [
        ".github/harden-runner/fork-org/allow_list.txt",
        ".github/harden-runner/allow_list.txt",
    ]
    upstream = ".github/harden-runner/lfreleng-actions/allow_list.txt"
    _install_fake_git(monkeypatch, files={upstream: "github.com:443\n"})
    result = rcs.fetch_file(
        host_org="fork-org",
        repo=".github",
        ref="main",
        candidates=cands,
        fallback_dir=".github/harden-runner",
        fallback_filename="allow_list.txt",
    )
    assert result["found"] is True
    assert result["fallback_used"] is True
    assert result["matched_path"] == upstream
    assert result["content"] == "github.com:443\n"


def test_fetch_file_fallback_ambiguous_stays_missing(monkeypatch):
    # Two org directories carry the file: the choice would be
    # ambiguous, so the miss stands.
    cands = [
        ".github/harden-runner/fork-org/allow_list.txt",
        ".github/harden-runner/allow_list.txt",
    ]
    _install_fake_git(
        monkeypatch,
        files={
            ".github/harden-runner/org-a/allow_list.txt": "a.example:443\n",
            ".github/harden-runner/org-b/allow_list.txt": "b.example:443\n",
        },
    )
    result = rcs.fetch_file(
        host_org="fork-org",
        repo=".github",
        ref="main",
        candidates=cands,
        fallback_dir=".github/harden-runner",
        fallback_filename="allow_list.txt",
    )
    assert result["found"] is False
    assert result["fallback_used"] is False


def test_fetch_file_fallback_ignores_other_filenames_and_depths(monkeypatch):
    # Only `<dir>/<org>/<filename>` entries count: other filenames and
    # deeper nesting are ignored, so a single valid entry still wins.
    cands = [
        ".github/harden-runner/fork-org/allow_list.txt",
        ".github/harden-runner/allow_list.txt",
    ]
    upstream = ".github/harden-runner/lfreleng-actions/allow_list.txt"
    _install_fake_git(
        monkeypatch,
        files={
            upstream: "github.com:443\n",
            ".github/harden-runner/org-a/other_list.txt": "x.example\n",
            ".github/harden-runner/org-b/nested/allow_list.txt": "y.example\n",
        },
    )
    result = rcs.fetch_file(
        host_org="fork-org",
        repo=".github",
        ref="main",
        candidates=cands,
        fallback_dir=".github/harden-runner",
        fallback_filename="allow_list.txt",
    )
    assert result["found"] is True
    assert result["fallback_used"] is True
    assert result["matched_path"] == upstream


def test_fetch_file_fallback_rejects_non_blob(monkeypatch):
    # A sole ls-tree match that is not a blob (e.g. a gitlink) must not
    # resolve: the fallback applies the same blob guard as the
    # candidate loop.
    upstream = ".github/harden-runner/lfreleng-actions/allow_list.txt"
    _install_fake_git(
        monkeypatch,
        files={upstream: "github.com:443\n"},
        trees=[upstream],
    )
    result = rcs.fetch_file(
        host_org="fork-org",
        repo=".github",
        ref="main",
        candidates=[
            ".github/harden-runner/fork-org/allow_list.txt",
            ".github/harden-runner/allow_list.txt",
        ],
        fallback_dir=".github/harden-runner",
        fallback_filename="allow_list.txt",
    )
    assert result["found"] is False
    assert result["fallback_used"] is False


def test_fetch_file_no_fallback_without_dir(monkeypatch):
    # Explicit-path mode passes no fallback coordinates: a miss stays a
    # miss even when an org file exists in the tree.
    _install_fake_git(
        monkeypatch,
        files={".github/harden-runner/lfreleng-actions/allow_list.txt": "h:443\n"},
    )
    result = rcs.fetch_file(
        host_org="fork-org",
        repo=".github",
        ref="main",
        candidates=["custom/dir/allow_list.txt"],
    )
    assert result["found"] is False
    assert result["fallback_used"] is False


def test_resolve_exposes_fallback_coordinates():
    resolved = _resolve("@deadbeef" + "0" * 32, org="fork-org")
    assert resolved["fallback_dir"] == ".github/python-audit"
    assert resolved["fallback_filename"] == "allow_list.txt"


def test_resolve_explicit_path_has_no_fallback():
    resolved = _resolve("lfit//configs/onap/list.txt@main")
    assert resolved["fallback_dir"] == ""
    assert resolved["fallback_filename"] == ""
