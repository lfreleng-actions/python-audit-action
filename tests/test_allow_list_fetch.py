# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Retry cover for the allow-list fetch (issue #290).

The default allow-list fetch made one ``curl`` request, so a single
HTTP 503 from raw.githubusercontent.com failed the audit. These tests
run the step's script, read out of ``action.yaml`` so they cannot
drift from it, against a stub ``curl`` scripted per attempt and a
stub ``sleep`` that records each delay instead of waiting.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
FETCH_STEP = "Resolve vulnerability allow-list"
EXPLICIT_URL = "https://example.invalid/allow_list.txt"
GOOD_BODY = "CVE-2024-0001\n"
PENDING = pytest.mark.xfail(strict=True, reason="retry not yet implemented")

# Plays back one scripted attempt per call. For each attempt N the
# scenario directory holds N.rc (curl exit code), N.code (HTTP status
# written as -w would), optionally N.ra (a Retry-After value) and N.body
# (written to the -o file whatever the exit code, as curl does with a
# partial transfer). Calls beyond the script fail the test loudly.
CURL_STUB = """#!/usr/bin/env bash
n=$(( $(cat "$STUB_DIR/count") + 1 ))
echo "$n" > "$STUB_DIR/count"
printf '%s\\n' "$@" > "$STUB_DIR/$n.args"
out=""
hdr=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -D) hdr="$2"; shift ;;
  esac
  shift
done
if [ ! -f "$STUB_DIR/$n.rc" ]; then
  echo "unscripted curl attempt $n" >&2
  exit 99
fi
code=$(cat "$STUB_DIR/$n.code")
if [ -n "$hdr" ]; then
  printf 'HTTP/2 %s\\r\\n' "$code" > "$hdr"
  if [ -f "$STUB_DIR/$n.ra" ]; then
    printf 'retry-after: %s\\r\\n' "$(cat "$STUB_DIR/$n.ra")" >> "$hdr"
  fi
  printf '\\r\\n' >> "$hdr"
fi
if [ -n "$out" ] && [ -f "$STUB_DIR/$n.body" ]; then
  cp "$STUB_DIR/$n.body" "$out"
fi
printf '%s' "$code"
exit "$(cat "$STUB_DIR/$n.rc")"
"""

# Prepended to the step as a shell function, so it runs in the step's
# own shell: it records each delay and, instead of waiting, moves bash's
# SECONDS clock forward by the delay plus the scripted skip for that
# sleep, which stands in for time the attempts took. A run's elapsed
# time is then known up to the one-second tick bash's clock may take.
SLEEP_PRELUDE = """sleep() {
  local k skip=0
  printf '%s\\n' "$1" >> "$STUB_DIR/sleeps"
  k=$(wc -l < "$STUB_DIR/sleeps")
  if [ -f "$STUB_DIR/skip.$k" ]; then
    skip=$(cat "$STUB_DIR/skip.$k")
  fi
  SECONDS=$(( SECONDS + $1 + skip ))
}
"""


class Attempt(NamedTuple):
    """One scripted curl attempt."""

    rc: int = 0
    code: str = "200"
    body: str = ""
    retry_after: str | None = None


class Result(NamedTuple):
    """What a run of the fetch step produced."""

    proc: subprocess.CompletedProcess[str]
    attempts: int
    sleeps: list[int]
    outputs: dict[str, str]
    max_times: list[int]


def _fetch_script() -> str:
    action = yaml.safe_load((REPO_ROOT / "action.yaml").read_text())
    for step in action["runs"]["steps"]:
        if step.get("name") == FETCH_STEP:
            return step["run"]
    raise AssertionError(f"step not found in action.yaml: {FETCH_STEP}")


def _max_time(args: list[str]) -> int:
    return int(args[args.index("--max-time") + 1])


@pytest.fixture(name="run_fetch")
def _run_fetch(tmp_path: Path):
    """Return a runner for the fetch step against scripted attempts."""

    def run(
        attempts: list[Attempt], url: str = "", skips: tuple[int, ...] = ()
    ) -> Result:
        stub_dir = tmp_path / "stub"
        bin_dir = tmp_path / "bin"
        stub_dir.mkdir()
        bin_dir.mkdir()
        (stub_dir / "count").write_text("0\n")
        for n, attempt in enumerate(attempts, start=1):
            (stub_dir / f"{n}.rc").write_text(f"{attempt.rc}\n")
            (stub_dir / f"{n}.code").write_text(attempt.code)
            (stub_dir / f"{n}.body").write_text(attempt.body)
            if attempt.retry_after is not None:
                (stub_dir / f"{n}.ra").write_text(attempt.retry_after)
        for k, skip in enumerate(skips, start=1):
            (stub_dir / f"skip.{k}").write_text(f"{skip}\n")
        stub = bin_dir / "curl"
        stub.write_text(CURL_STUB)
        stub.chmod(0o755)
        output = tmp_path / "github_output"
        output.touch()
        script = tmp_path / "fetch-step.sh"
        script.write_text(SLEEP_PRELUDE + _fetch_script())

        env = dict(os.environ)
        env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
        env["STUB_DIR"] = str(stub_dir)
        env["GITHUB_OUTPUT"] = str(output)
        env.pop("GITHUB_STEP_SUMMARY", None)
        env.update(
            ALLOW_LIST_PATH="",
            ALLOW_LIST_URL=url,
            ALLOW_LIST_ORG="",
            ALLOW_LIST_DISABLE="false",
            ALLOW_LIST_SUMMARY="false",
            REPO_OWNER="example-org",
        )
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env=env,
            cwd=tmp_path,
            check=False,
        )
        count = int((stub_dir / "count").read_text())
        sleeps_file = stub_dir / "sleeps"
        sleeps = (
            [int(s) for s in sleeps_file.read_text().split()]
            if sleeps_file.exists()
            else []
        )
        outputs = dict(
            line.split("=", 1) for line in output.read_text().splitlines() if line
        )
        max_times = [
            _max_time((stub_dir / f"{n}.args").read_text().splitlines())
            for n in range(1, count + 1)
        ]
        return Result(proc, count, sleeps, outputs, max_times)

    return run


def _log(result: Result) -> str:
    return result.proc.stdout + result.proc.stderr


def _warnings(result: Result) -> list[str]:
    return [line for line in result.proc.stdout.splitlines() if "::warning::" in line]


@PENDING
def test_503_then_200_succeeds_with_one_warning(run_fetch):
    """A single 503 blip is retried and the list still loads."""
    result = run_fetch(
        [Attempt(code="503", body="Service Unavailable"), Attempt(body=GOOD_BODY)]
    )
    assert result.proc.returncode == 0, _log(result)
    assert result.attempts == 2
    assert result.sleeps == [2]
    warnings = _warnings(result)
    assert len(warnings) == 1, warnings
    assert "HTTP 503" in warnings[0], warnings
    assert "attempt 1" in warnings[0], warnings
    assert "2s" in warnings[0], warnings
    assert result.outputs["ids"] == "CVE-2024-0001"
    assert result.outputs["source"] == "default-url"


@PENDING
def test_connection_errors_then_200_succeeds(run_fetch):
    """Connection refused (7) then timeout (28) are both retried."""
    result = run_fetch(
        [
            Attempt(rc=7, code="000"),
            Attempt(rc=28, code="000"),
            Attempt(body=GOOD_BODY),
        ]
    )
    assert result.proc.returncode == 0, _log(result)
    assert result.attempts == 3
    assert result.sleeps == [2, 5]
    warnings = _warnings(result)
    assert "curl exit 7" in warnings[0], warnings
    assert "curl exit 28" in warnings[1], warnings
    assert result.outputs["ids"] == "CVE-2024-0001"


@PENDING
def test_persistent_503_fails_after_full_schedule(run_fetch):
    """An outage outlasting the schedule fails and counts the attempts."""
    result = run_fetch([Attempt(code="503", body="Service Unavailable")] * 5)
    assert result.proc.returncode != 0, _log(result)
    assert result.attempts == 5
    assert result.sleeps == [2, 5, 10, 20]
    assert len(_warnings(result)) == 4
    errors = [line for line in result.proc.stdout.splitlines() if "::error::" in line]
    assert len(errors) == 1, errors
    assert "HTTP 503" in errors[0], errors
    assert "5 attempts" in errors[0], errors


def test_every_attempt_bounded_by_max_time(run_fetch):
    """Each attempt keeps a per-attempt --max-time of at most 15s."""
    result = run_fetch([Attempt(code="503")] * 5)
    assert result.max_times, _log(result)
    assert all(0 < t <= 15 for t in result.max_times), result.max_times


@PENDING
def test_attempt_time_shrinks_to_remaining_budget(run_fetch):
    """An attempt late in the 90s bound gets only the time left.

    The clock jumps 78s at the first sleep, so the second attempt
    starts 80s in and its --max-time drops from 15 to the 10s left.
    """
    result = run_fetch([Attempt(code="503"), Attempt(body=GOOD_BODY)], skips=(78,))
    assert result.proc.returncode == 0, _log(result)
    assert result.max_times[0] == 15, result.max_times
    assert 9 <= result.max_times[1] <= 10, result.max_times


@PENDING
def test_retry_refused_when_delay_exhausts_budget(run_fetch):
    """No retry starts whose delay would end past the 90s bound.

    The clock reads 86s after the first sleep, so the second retry's
    5s delay would end past 90s: the step fails instead of sleeping.
    """
    result = run_fetch([Attempt(code="503")] * 3, skips=(84,))
    assert result.proc.returncode != 0, _log(result)
    assert result.attempts == 2
    assert result.sleeps == [2]
    assert 1 <= result.max_times[1] <= 4, result.max_times
    errors = [line for line in result.proc.stdout.splitlines() if "::error::" in line]
    assert len(errors) == 1, errors
    assert "2 attempts" in errors[0], errors


def test_default_url_404_is_soft_miss_without_retry(run_fetch):
    """No central list published: proceed on the first attempt."""
    result = run_fetch([Attempt(code="404", body="Not Found")])
    assert result.proc.returncode == 0, _log(result)
    assert result.attempts == 1
    assert result.sleeps == []
    assert result.outputs["source"] == "default-url-missing"
    assert result.outputs["ids"] == ""


def test_explicit_url_404_fails_without_retry(run_fetch):
    """A caller-supplied URL that is missing is a hard failure."""
    result = run_fetch([Attempt(code="404", body="Not Found")], url=EXPLICIT_URL)
    assert result.proc.returncode != 0, _log(result)
    assert result.attempts == 1
    assert result.sleeps == []
    assert "HTTP 404" in result.proc.stdout


@PENDING
@pytest.mark.parametrize(
    "attempt",
    [
        pytest.param(Attempt(code="400", body="Bad Request"), id="http-400"),
        pytest.param(Attempt(rc=63, code="200", body="CVE-"), id="max-filesize"),
    ],
)
def test_permanent_errors_fail_without_retry(run_fetch, attempt):
    """Other 4xx statuses and an oversized list fail at once."""
    result = run_fetch([attempt])
    assert result.proc.returncode != 0, _log(result)
    assert result.attempts == 1
    assert result.sleeps == []
    assert "1 attempt" in result.proc.stdout, result.proc.stdout


@PENDING
@pytest.mark.parametrize(
    ("retry_after", "expected"),
    [("3", 3), ("600", 30)],
    ids=["honoured", "capped"],
)
def test_retry_after_is_honoured_and_capped(run_fetch, retry_after, expected):
    """A 429 waits for the server's Retry-After, up to the cap."""
    result = run_fetch(
        [Attempt(code="429", retry_after=retry_after), Attempt(body=GOOD_BODY)]
    )
    assert result.proc.returncode == 0, _log(result)
    assert result.sleeps == [expected]


@PENDING
def test_partial_body_never_reaches_parser(run_fetch):
    """A failed attempt's body is discarded, not parsed.

    The first attempt dies mid-transfer (curl exit 56) after writing a
    token the parser rejects; were it parsed, the step would fail.
    """
    result = run_fetch(
        [
            Attempt(rc=56, code="200", body="CVE-2024-0002\nnot-an-id"),
            Attempt(body=GOOD_BODY),
        ]
    )
    assert result.proc.returncode == 0, _log(result)
    assert result.outputs["ids"] == "CVE-2024-0001"
    assert "not-an-id" not in result.proc.stdout
