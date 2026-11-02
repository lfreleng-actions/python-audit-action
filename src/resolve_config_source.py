# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║  SYNCHRONISED FILE — DO NOT EDIT IN ISOLATION                      ║
# ║                                                                    ║
# ║  This file is mirrored, byte-for-byte, across two repositories:    ║
# ║    - lfreleng-actions/python-audit-action       : src/...          ║
# ║    - lfreleng-actions/harden-runner-block-action: src/...          ║
# ║                                                                    ║
# ║  The `config` input grammar and its resolution/fetch/sanitise      ║
# ║  behaviour MUST stay identical in both actions. Any change here    ║
# ║  has to be raised as PAIRED pull requests in BOTH repositories.    ║
# ║  A CI check in each repo diffs this file against the other repo's  ║
# ║  copy and fails the build if they diverge.                         ║
# ║                                                                    ║
# ║  The only action-specific behaviour is selected at call time via   ║
# ║  the --mode flag (endpoints | vulns); the module itself carries    ║
# ║  no per-action constants.                                          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# resolve_config_source.py
#
# Resolves the `config` input (a GitHub-Actions `uses:`-style coordinate)
# into a concrete (host-org, repo, ref, in-repo path) tuple, fetches the
# referenced file from GitHub using a shallow, ref-pinned git fetch, and
# sanitises the content against a strict, mode-selected token grammar.
#
# The module performs NO publishing of its own: it prints results to the
# destinations its caller selects (JSON to stdout, key=value lines to a
# GITHUB_OUTPUT file, a markdown block to a GITHUB_STEP_SUMMARY file).
# Diagnostics and errors go to stderr. Workflow commands (::error::,
# ::add-mask::) are intentionally NOT emitted here so that stdout stays
# clean JSON for the Node.js consumer; the calling wrapper is responsible
# for masking the token and surfacing errors as workflow annotations.
#
# Exit codes:
#   0  success (file found and sanitised) OR a "soft" not-found at an
#      auto-derived path (the JSON carries found=false; the caller
#      decides whether that is fatal for its action)
#   1  hard error (bad input, validation failure, network/git failure)

# pyright: basic

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable

# Hard ceiling on the file size we will read out of the fetched tree, to
# stop a misconfigured or hostile repo from exhausting runner memory.
MAX_FILE_BYTES = 1_048_576  # 1 MiB

# GitHub org/user names: 1-39 chars, alphanumerics and single hyphens,
# no leading/trailing hyphen, no consecutive hyphens.
ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")

# Repository names: alphanumerics plus '.', '_', '-'. The canonical host
# repo is the special '.github' repo, so a leading dot must be allowed.
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# A single in-repo path segment. No empty segments, no '..', no slashes
# (the path is split on '/' before validation), no shell metacharacters.
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Git ref: branch name, tag name, or commit SHA. Conservative subset of
# the characters git permits, sufficient for our use and safe to hand to
# the git CLI as a positional argument.
REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

# Seconds to wait before each retry of a transiently refused fetch; one
# more attempt is made than there are entries here.
FETCH_BACKOFF_SECONDS = (2, 5)

# Fetch failures that no retry can fix: the ref, the repository or the
# credential is wrong.
_FATAL_FETCH_RE = re.compile(
    r"couldn't find remote ref|not our ref|Repository not found",
    re.IGNORECASE,
)

# The HTTP status git reports, in either of the shapes it uses:
# "The requested URL returned error: 403" or "RPC failed; HTTP 503".
_HTTP_STATUS_RE = re.compile(r"(?:returned error:|\bHTTP)\s*(\d{3})\b")

# Connection-level failures that a later attempt may not hit.
_TRANSIENT_FETCH_RE = re.compile(
    r"Could not resolve host|Failed to connect|Connection reset"
    r"|Operation timed out|early EOF|RPC failed",
    re.IGNORECASE,
)


class ResolveError(Exception):
    """A hard error that must fail the action."""


# ---------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------


def split_comment(value: str) -> tuple[str, str]:
    """Split a trailing ' #...' comment (one or more spaces/tabs before '#').

    Returns (spec, comment). The comment (without the leading whitespace
    and '#') is informational only and never affects resolution.

    Only spaces and tabs are treated as the separator before '#': a
    newline must NOT be consumed here, otherwise a value such as
    'lfit@main\n# hidden' would be split into a bare spec plus a
    'comment' and slip past the newline rejection in parse_config().
    """
    # Match the first run of spaces/tabs followed by '#', to end of line.
    m = re.search(r"[ \t]+#[^\r\n]*$", value)
    if m:
        comment = value[m.start() :].lstrip(" \t")[1:].strip()
        return value[: m.start()], comment
    return value, ""


def parse_config(spec: str) -> dict:
    """Parse a `config` spec into its raw components.

    Grammar:
        <spec>     ::= <source> [ "@" <ref> ]
        <source>   ::= <repospec> [ "//" <subpath> ]
        <repospec> ::= [ <host-org> [ "/" <repo> ] ]
        <subpath>  ::= [ <dir> "/" ]... [ <filename> ]
    """
    if "\n" in spec or "\r" in spec:
        raise ResolveError("config must not contain newline characters")

    # Separate an optional '@<ref>'. '@' may appear at most once.
    ref = ""
    if "@" in spec:
        source, _, ref = spec.partition("@")
        if "@" in ref:
            raise ResolveError("config contains more than one '@' separator")
        if ref == "":
            raise ResolveError("config has an empty ref after '@'")
    else:
        source = spec

    # Separate repospec from subpath on '//'. '//' may appear at most once.
    subpath = ""
    has_subpath = False
    if "//" in source:
        repospec, _, subpath = source.partition("//")
        has_subpath = True
        if "//" in subpath:
            raise ResolveError("config contains more than one '//' separator")
    else:
        repospec = source

    return {
        "repospec": repospec,
        "subpath": subpath,
        "has_subpath": has_subpath,
        "ref": ref,
    }


def resolve(
    spec: str,
    *,
    workflow_org: str,
    family: str,
    default_repo: str = ".github",
    default_filename: str = "allow_list.txt",
) -> dict:
    """Resolve a parsed config spec into concrete fetch coordinates.

    Returns a dict with: host_org, repo, ref, candidates (ordered list of
    in-repo paths to try), path_explicit (bool), comment.
    """
    spec, comment = split_comment(spec.strip())
    if spec == "":
        raise ResolveError("config is empty")

    parts = parse_config(spec)

    # --- host-org and repo (the part before '//') ---
    repospec = parts["repospec"].strip("/")
    if repospec == "":
        host_org = workflow_org
        repo = default_repo
    else:
        segs = repospec.split("/")
        if len(segs) == 1:
            host_org, repo = segs[0], default_repo
        elif len(segs) == 2:
            host_org, repo = segs[0], segs[1]
        else:
            raise ResolveError(
                "config repository part accepts at most '<org>/<repo>'; "
                "put any in-repo path after '//'"
            )

    if host_org == "":
        host_org = workflow_org
    if not ORG_RE.match(host_org):
        raise ResolveError(f"invalid host org in config: '{host_org}'")
    if repo == "":
        repo = default_repo
    if repo in ("..", ".") or not REPO_RE.match(repo):
        raise ResolveError(f"invalid repository in config: '{repo}'")

    # --- ref ---
    ref = parts["ref"] or "HEAD"
    if ref != "HEAD":
        if (
            ref.startswith("-")
            or ref.startswith("/")
            or ".." in ref
            or "@{" in ref
            or len(ref) > 255
            or not REF_RE.match(ref)
        ):
            raise ResolveError(f"invalid git ref in config: '{ref}'")

    # --- subpath -> filename + directory + search candidates ---
    default_dir_specific = f".github/{family}/{workflow_org}"
    default_dir_family = f".github/{family}"

    subpath = parts["subpath"]
    path_explicit = False
    fallback_dir = ""
    fallback_filename = ""

    if not parts["has_subpath"] or subpath == "":
        # No subpath, or a bare '//': default dir search chain + default file.
        filename = default_filename
        candidates = [
            f"{default_dir_specific}/{filename}",
            f"{default_dir_family}/{filename}",
        ]
        fallback_dir = default_dir_family
        fallback_filename = filename
    elif "/" not in subpath:
        # Filename only: override the filename, keep the default dir search.
        filename = subpath
        candidates = [
            f"{default_dir_specific}/{filename}",
            f"{default_dir_family}/{filename}",
        ]
        fallback_dir = default_dir_family
        fallback_filename = filename
    else:
        # Explicit directory present: use exactly this path, no search.
        path_explicit = True
        candidates = [subpath]

    # Validate every candidate path segment.
    for cand in candidates:
        if cand.startswith("/") or "\\" in cand or ".." in cand.split("/"):
            raise ResolveError(f"invalid in-repo path in config: '{cand}'")
        segs = cand.split("/")
        if not segs or any(seg == "" for seg in segs):
            raise ResolveError(f"invalid in-repo path in config: '{cand}'")
        for seg in segs:
            if not SEGMENT_RE.match(seg):
                raise ResolveError(
                    f"invalid path segment '{seg}' in config path '{cand}'"
                )

    if workflow_org != "" and not ORG_RE.match(workflow_org):
        raise ResolveError(f"invalid workflow org: '{workflow_org}'")

    return {
        "host_org": host_org,
        "repo": repo,
        "ref": ref,
        "candidates": candidates,
        "path_explicit": path_explicit,
        "fallback_dir": fallback_dir,
        "fallback_filename": fallback_filename,
        "comment": comment,
    }


# ---------------------------------------------------------------------
# Fetch (shallow, ref-pinned, git over HTTPS)
# ---------------------------------------------------------------------


def _run_git(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _transient_fetch_failure(stderr: str) -> str:
    """Name a fetch failure worth retrying, or return '' when it is not.

    A refused or dropped request (HTTP 403, 408, 429, 5xx, or a
    connection-level error) may succeed on a later attempt. An unknown
    ref, a missing repository, HTTP 401 or 404, or anything unrecognised
    will not, so those return '' and fail at once.
    """
    if _FATAL_FETCH_RE.search(stderr):
        return ""
    status = _HTTP_STATUS_RE.search(stderr)
    if status:
        code = int(status.group(1))
        if code in (403, 408, 429) or 500 <= code <= 599:
            return f"HTTP {code}"
        return ""
    connection = _TRANSIENT_FETCH_RE.search(stderr)
    return connection.group(0) if connection else ""


def fetch_file(
    *,
    host_org: str,
    repo: str,
    ref: str,
    candidates: list[str],
    token: str = "",
    timeout: int = 30,
    fallback_dir: str = "",
    fallback_filename: str = "",
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Shallow-fetch `ref` and return the first existing candidate file.

    Works uniformly for branches, tags and commit SHAs: GitHub honours
    `git fetch --depth 1 <sha>` for reachable commits. Returns a dict with
    found (bool), resolved_sha, matched_path, content (str | None) and
    fallback_used (bool).

    A fetch that fails transiently (GitHub refusing or dropping the
    request) is retried after each delay in FETCH_BACKOFF_SECONDS, so
    long as the retry fits inside `timeout`. Every fetch gets only the
    time left before that deadline, and no retry starts once it has
    passed. `sleep` performs the wait and `clock` reads the time; both
    exist so tests can skip real waiting. Each retry logs one line to
    stderr.

    When every candidate misses and `fallback_dir`/`fallback_filename`
    name an auto-derived search root, the fetched tree is scanned for
    `<fallback_dir>/<org>/<fallback_filename>` entries. A single match
    resolves as a "sole-org fallback": forks carry the upstream org's
    file at the pinned ref but derive a different workflow org, so the
    org-specific candidate can never match there even though exactly
    one (byte-identical, ref-pinned) list exists in the tree. Zero or
    several matches keep the miss (several would make the choice
    ambiguous).
    """
    url = f"https://github.com/{host_org}/{repo}.git"
    with tempfile.TemporaryDirectory() as tmp:

        def git(args: list[str]) -> subprocess.CompletedProcess:
            return _run_git(["-C", tmp, *args], timeout)

        if git(["init", "-q"]).returncode != 0:
            raise ResolveError("git init failed")
        if git(["remote", "add", "origin", url]).returncode != 0:
            raise ResolveError("git remote add failed")

        if token:
            # Inject auth as a git config header. We write it straight
            # into the repo's local config file rather than via
            # `git config <key> <value>`, because the latter would place
            # the credential in a child process's argv (visible in
            # process listings). Writing the file keeps the token off
            # the command line entirely; it is also never placed in the
            # remote URL.
            basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            config_path = os.path.join(tmp, ".git", "config")
            header_line = f"\textraheader = AUTHORIZATION: basic {basic}\n"
            try:
                with open(config_path, "a", encoding="utf-8") as fh:
                    fh.write('[http "https://github.com/"]\n')
                    fh.write(header_line)
            except OSError as exc:
                raise ResolveError(f"git auth header configuration failed: {exc}")

        fetch_args = [
            "-c",
            "protocol.version=2",
            "fetch",
            "-q",
            "--depth",
            "1",
            "origin",
            ref,
        ]
        attempts = len(FETCH_BACKOFF_SECONDS) + 1
        deadline = clock() + timeout
        remaining = float(timeout)
        attempt = 1
        while True:
            fetched = _run_git(["-C", tmp, *fetch_args], remaining)
            if fetched.returncode == 0:
                break
            stderr = fetched.stderr.strip()
            message = f"git fetch of '{ref}' from {host_org}/{repo} failed: {stderr}"
            transient = _transient_fetch_failure(stderr)
            if not transient:
                raise ResolveError(message)
            # Every earlier attempt was transient too, or the loop would
            # have stopped there, so the whole run was a refusal.
            times = "once" if attempt == 1 else f"{attempt} times"
            refused = ResolveError(
                f"{message}; GitHub refused the fetch {times} ({transient}); "
                "the ref may still be valid, see the retry log"
            )
            delay = FETCH_BACKOFF_SECONDS[attempt - 1] if attempt < attempts else 0
            if attempt >= attempts or delay >= deadline - clock():
                raise refused
            print(
                f"fetch attempt {attempt} of {attempts} failed ({transient}); "
                f"retrying in {delay} s",
                file=sys.stderr,
            )
            sleep(delay)
            # The wait may overrun its delay; never start a fetch the
            # deadline has no time left for.
            remaining = deadline - clock()
            if remaining <= 0:
                raise refused
            attempt += 1

        # Peel to the underlying commit. For an annotated tag,
        # FETCH_HEAD can name the tag object rather than the commit it
        # points at; '^{commit}' dereferences it so resolved_sha is
        # always a commit SHA, consistent across branch, lightweight
        # tag, annotated tag and commit-SHA refs.
        rev = git(["rev-parse", "FETCH_HEAD^{commit}"])
        if rev.returncode != 0:
            raise ResolveError("could not resolve FETCH_HEAD to a commit SHA")
        resolved_sha = rev.stdout.strip()

        for cand in candidates:
            # Use 'cat-file -t' (not '-e'): '-e' also succeeds for a
            # tree, and 'git show <commit>:<dir>' would then print a
            # directory listing that we'd mistake for file content.
            # Only accept a blob, matching the local-path mode's
            # regular-file requirement.
            typ = git(["cat-file", "-t", f"{resolved_sha}:{cand}"])
            if typ.returncode != 0 or typ.stdout.strip() != "blob":
                continue
            size = git(["cat-file", "-s", f"{resolved_sha}:{cand}"])
            try:
                if size.returncode == 0 and int(size.stdout.strip()) > MAX_FILE_BYTES:
                    raise ResolveError(
                        f"config file '{cand}' exceeds {MAX_FILE_BYTES}-byte limit"
                    )
            except ValueError:
                pass
            shown = git(["show", f"{resolved_sha}:{cand}"])
            if shown.returncode != 0:
                continue
            return {
                "found": True,
                "resolved_sha": resolved_sha,
                "matched_path": cand,
                "content": shown.stdout,
                "fallback_used": False,
            }

        if fallback_dir and fallback_filename:
            listed = git(["ls-tree", "-r", "--name-only", resolved_sha, fallback_dir])
            if listed.returncode == 0:
                matches = []
                for line in listed.stdout.splitlines():
                    line = line.strip()
                    if not line.startswith(f"{fallback_dir}/"):
                        continue
                    rel = line[len(fallback_dir) + 1 :]
                    segs = rel.split("/")
                    # Exactly one org directory between the family dir
                    # and the filename, with a safe path segment (never
                    # '.' or '..', matching resolve()'s validation), and
                    # not a candidate we already tried above.
                    if (
                        len(segs) == 2
                        and segs[1] == fallback_filename
                        and segs[0] not in (".", "..")
                        and SEGMENT_RE.match(segs[0])
                        and line not in candidates
                    ):
                        matches.append(line)
                if len(matches) == 1:
                    cand = matches[0]
                    # Same blob guard as the candidate loop above: only
                    # accept regular files, not trees or gitlinks.
                    typ = git(["cat-file", "-t", f"{resolved_sha}:{cand}"])
                    if typ.returncode == 0 and typ.stdout.strip() == "blob":
                        size = git(["cat-file", "-s", f"{resolved_sha}:{cand}"])
                        try:
                            if (
                                size.returncode == 0
                                and int(size.stdout.strip()) > MAX_FILE_BYTES
                            ):
                                raise ResolveError(
                                    f"config file '{cand}' exceeds "
                                    f"{MAX_FILE_BYTES}-byte limit"
                                )
                        except ValueError:
                            pass
                        shown = git(["show", f"{resolved_sha}:{cand}"])
                        if shown.returncode == 0:
                            return {
                                "found": True,
                                "resolved_sha": resolved_sha,
                                "matched_path": cand,
                                "content": shown.stdout,
                                "fallback_used": True,
                            }
                elif len(matches) > 1:
                    print(
                        "sole-org fallback skipped: files named "
                        f"'{fallback_filename}' exist under more than one "
                        f"org directory in '{fallback_dir}/' "
                        f"({len(matches)} matches); the choice would be "
                        "ambiguous",
                        file=sys.stderr,
                    )

        return {
            "found": False,
            "resolved_sha": resolved_sha,
            "matched_path": "",
            "content": None,
            "fallback_used": False,
        }


# ---------------------------------------------------------------------
# Sanitisation (mode-selected)
# ---------------------------------------------------------------------


def _strip_comments_and_split(raw: str) -> list[str]:
    text = raw.lstrip("\ufeff")
    # Remove '#' comments (full-line and trailing-after-whitespace).
    text = re.sub(r"(^|[ \t])#[^\r\n]*", r"\1", text, flags=re.MULTILINE)
    text = re.sub(r"\s+", " ", text).strip()
    if text == "":
        return []
    return text.split(" ")


_HOST_BARE = r"[A-Za-z0-9][A-Za-z0-9.-]*"
_HOST_WILD = r"\*\.[A-Za-z0-9][A-Za-z0-9.-]*"
_ENDPOINT_RE = re.compile(rf"^(?:{_HOST_BARE}|{_HOST_WILD})(?::[0-9]{{1,5}})?$")

_VULN_RE = re.compile(
    r"^(?:"
    r"CVE-[0-9]{4}-[0-9]{4,}"
    r"|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
    r"|PYSEC-[0-9]{4}-[0-9]+"
    r"|OSV-[0-9]{4}-[0-9]+"
    r"|PVE-[0-9]+(?:-[0-9]+)?"
    r")$"
)


def sanitise(raw: str, mode: str) -> list[str]:
    """Validate every token in the file against the mode's grammar.

    A single non-conforming token is a hard error rather than being
    silently dropped, so untrusted remote content cannot smuggle
    unexpected values into a downstream tool.
    """
    tokens = _strip_comments_and_split(raw)
    if not tokens:
        raise ResolveError("config file is empty after parsing")

    for token in tokens:
        if mode == "endpoints":
            if not _ENDPOINT_RE.match(token):
                raise ResolveError(
                    f"rejected endpoint token '{token}' "
                    "(must be host[:port] or *.host[:port])"
                )
            if ":" in token:
                port = token.rsplit(":", 1)[1]
                if not port.isdigit() or not (1 <= int(port) <= 65535):
                    raise ResolveError(
                        f"rejected endpoint token '{token}' (port out of range 1-65535)"
                    )
        elif mode == "vulns":
            if not _VULN_RE.match(token):
                raise ResolveError(
                    f"rejected vulnerability token '{token}' "
                    "(not a recognised CVE/GHSA/PYSEC/OSV/PVE ID)"
                )
        else:
            raise ResolveError(f"unknown mode: '{mode}'")

    return tokens


# ---------------------------------------------------------------------
# Emit helpers
# ---------------------------------------------------------------------


def _append(path: str, text: str) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def write_github_output(path: str, content_key: str, result: dict) -> None:
    if not path:
        return
    sep = " "
    pairs = {
        content_key: sep.join(result["tokens"]),
        "count": str(result["count"]),
        "found": "true" if result["found"] else "false",
        "path_explicit": "true" if result["path_explicit"] else "false",
        "resolved_host_org": result["host_org"],
        "resolved_repo": result["repo"],
        "resolved_ref": result["ref"],
        "resolved_sha": result["resolved_sha"],
        "resolved_path": result["matched_path"],
        "matched_candidate": result["matched_candidate"],
        "source": "config",
    }
    lines = []
    for key, value in pairs.items():
        if "\n" in value or "\r" in value:
            raise ResolveError(f"refusing to write multi-line output '{key}'")
        lines.append(f"{key}={value}\n")
    _append(path, "".join(lines))


def write_step_summary(path: str, title: str, unit: str, result: dict) -> None:
    if not path or not title:
        return
    expanded = (
        f"{result['host_org']}/{result['repo']}/"
        f"{result['matched_path']}@{result['ref']}"
        if result["found"]
        else "(none found)"
    )
    lines = [
        f"### {title}",
        "",
        "- Source: `config`",
        f"- Resolved: `{expanded}`",
        f"- Commit SHA: `{result['resolved_sha'] or '(n/a)'}`",
        f"- Matched candidate: {result['matched_candidate'] or '(none)'}",
        f"- {unit} loaded: **{result['count']}**",
        "",
    ]
    _append(path, "\n".join(lines))


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Resolve and fetch a `config` allow-list source."
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--workflow-org", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--mode", required=True, choices=["endpoints", "vulns"])
    parser.add_argument("--token", default="")
    parser.add_argument(
        "--token-env",
        default="",
        help=(
            "Name of an environment variable holding the token. Preferred "
            "over --token so the secret never appears in the process "
            "argument list. Takes precedence over --token when set."
        ),
    )
    parser.add_argument("--default-repo", default=".github")
    parser.add_argument("--default-filename", default="allow_list.txt")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--content-key", default="ids")
    parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    parser.add_argument(
        "--step-summary", default=os.environ.get("GITHUB_STEP_SUMMARY", "")
    )
    parser.add_argument("--summary-title", default="")
    parser.add_argument("--summary-unit", default="Entries")
    parser.add_argument("--json-stdout", action="store_true")
    args = parser.parse_args(argv)

    token = args.token
    if args.token_env:
        token = os.environ.get(args.token_env, "")
        # Drop the secret from the environment immediately after reading
        # it, so the git subprocesses spawned below (which inherit
        # os.environ) do not carry the token in their environment. The
        # credential reaches git only via the repo-local config header.
        os.environ.pop(args.token_env, None)

    try:
        resolved = resolve(
            args.config,
            workflow_org=args.workflow_org,
            family=args.family,
            default_repo=args.default_repo,
            default_filename=args.default_filename,
        )
        fetched = fetch_file(
            host_org=resolved["host_org"],
            repo=resolved["repo"],
            ref=resolved["ref"],
            candidates=resolved["candidates"],
            token=token,
            timeout=args.timeout,
            fallback_dir=resolved["fallback_dir"],
            fallback_filename=resolved["fallback_filename"],
        )

        tokens: list[str] = []
        matched_candidate = ""
        if fetched["found"]:
            tokens = sanitise(fetched["content"], args.mode)
            if fetched["fallback_used"]:
                matched_candidate = "sole-org-fallback"
            elif fetched["matched_path"] == resolved["candidates"][0]:
                matched_candidate = (
                    "explicit" if resolved["path_explicit"] else "org-specific"
                )
            else:
                matched_candidate = "family-default"
        elif resolved["path_explicit"]:
            # An explicitly-named file that is missing is always a hard
            # error: the caller asked for that exact path. Only a miss at
            # an auto-derived (searched) path is "soft" and left for the
            # calling action to interpret via the found=false result.
            raise ResolveError(
                "config file not found at explicit path "
                f"'{resolved['candidates'][0]}' in "
                f"{resolved['host_org']}/{resolved['repo']}@{resolved['ref']}"
            )

        result = {
            "found": fetched["found"],
            "path_explicit": resolved["path_explicit"],
            "host_org": resolved["host_org"],
            "repo": resolved["repo"],
            "ref": resolved["ref"],
            "resolved_sha": fetched["resolved_sha"],
            "matched_path": fetched["matched_path"],
            "matched_candidate": matched_candidate,
            "comment": resolved["comment"],
            "tokens": tokens,
            "count": len(tokens),
        }

        write_github_output(args.github_output, args.content_key, result)
        write_step_summary(
            args.step_summary, args.summary_title, args.summary_unit, result
        )
        if args.json_stdout:
            print(json.dumps(result))
        return 0
    except ResolveError as exc:
        print(f"config resolution error: {exc}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("config resolution error: git operation timed out", file=sys.stderr)
        return 1
    except FileNotFoundError:
        # 'git' is not installed / not on PATH.
        print(
            "config resolution error: the 'git' executable was not found",
            file=sys.stderr,
        )
        return 1
    except UnicodeDecodeError:
        # A fetched blob (or git output) was not valid UTF-8.
        print(
            "config resolution error: fetched content is not valid UTF-8",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        # Any other failure spawning git or reading/writing files.
        print(f"config resolution error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
