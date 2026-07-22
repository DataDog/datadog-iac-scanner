"""Command-line interface for the performance-regression benchmark."""

from __future__ import annotations

import argparse
import logging
import shutil
import time
from pathlib import Path

from .benchmark import run
from .models import (
    DEFAULT_OUTPUT,
    DEFAULT_RUNS,
    DEFAULT_WORK_DIR,
    CliArgs,
    Trigger,
)

log = logging.getLogger("regression")

DESCRIPTION = """IaC scanner/rules performance-regression benchmark.

Runs the scanner against a corpus of repositories under a *candidate* build and
one or more *baselines*, measures wall time / CPU / peak memory / finding
counts for each, and renders a Markdown PR comment summarising the deltas.

The same script is invoked from both CI pipelines; only ``--trigger`` differs:

  * ``--trigger scanner`` — a PR in datadog-iac-scanner. The scanner binary is
    the variable; rules are held fixed. Baselines are the scanner's ``main``
    branch and its latest released tag (semver ``vX.Y.Z``, pre-releases like
    ``-alpha`` excluded).
  * ``--trigger rules`` — a PR in datadog-iac-scanner-default-rules. The rules
    are the variable; the scanner is held fixed (latest released tag). The only
    baseline is the rules' ``main`` branch.

Rules come from a local default-rules checkout when present.
With ``--remote-rules`` (or when no local checkout is found under --repos-dir),
the scanner instead fetches the deployed default ruleset from the Datadog
backend at runtime, so no rules clone is needed. Remote rules are held fixed for
every variant, so they only apply to ``--trigger scanner``; ``--trigger rules``
requires a local checkout because it varies the ruleset per variant.

A run needs a clone of the scanner repository plus the corpus repositories, and
(unless running with remote rules) the rules repository. The scanner checkout is
discovered from this entrypoint; other clones default to its parent directory.

Deliberately dependency-free (Python 3.10+ stdlib only): measurement uses
os.fork/os.wait4 rusage, so CI needs no ``pip install`` step.
"""


def parse_args(argv: list[str] | None = None) -> CliArgs:
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = parser.add_argument(
        "--trigger",
        required=True,
        type=Trigger,
        choices=list(Trigger),
        help="which repo's PR triggered this run",
    )
    _ = parser.add_argument(
        "--repos-dir",
        help="directory containing the default-rules and optional corpus clones "
        + "(default: scanner repository parent)",
    )
    _ = parser.add_argument(
        "--corpus-config",
        help="override the bundled corpus repository list",
    )
    _ = parser.add_argument(
        "--work-dir",
        help=f"scratch directory for worktrees, builds and clones (default: {DEFAULT_WORK_DIR})",
    )
    _ = parser.add_argument(
        "--runs",
        type=_positive_int,
        help=f"scan repetitions per variant/repo (default: {DEFAULT_RUNS})",
    )
    _ = parser.add_argument(
        "--no-warmup",
        dest="warmup",
        action="store_false",
        help="skip the discarded per-repo warmup scan that warms the OS file cache",
    )
    _ = parser.add_argument(
        "--platforms",
        help="comma-separated platform types to scan (default: all)",
    )
    _ = parser.add_argument(
        "--remote-rules",
        action="store_true",
        help="skip the local rules checkout and let the scanner fetch the "
        + "deployed default ruleset from the Datadog backend at runtime "
        + "(scanner trigger only; the default when no local rules checkout is found)",
    )
    _ = parser.add_argument(
        "--gitretriever-url",
        help="gitretriever base URL for cloning corpus repos",
    )
    _ = parser.add_argument(
        "--gitretriever-token",
        help="gitretriever Bearer token (default: $GITRETRIEVER_TOKEN)",
    )
    _ = parser.add_argument(
        "--output",
        help=f"path to write the rendered Markdown PR comment (default: {DEFAULT_OUTPUT})",
    )
    _ = parser.add_argument(
        "--json-output",
        help="optional path to write a machine-readable JSON summary",
    )
    _ = parser.add_argument(
        "--public",
        action=argparse.BooleanOptionalAction,
        help="redact repository identities and report finding-count changes as "
        + "percentage deltas only, for posting to a public repo "
        + "(default: enabled when $CI is set)",
    )
    _ = parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv, namespace=CliArgs())


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def main(argv: list[str] | None = None) -> int:
    started_at = time.monotonic()
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if not shutil.which("go"):
        log.error("`go` toolchain not found on PATH; cannot build the scanner")
        return 2
    try:
        markdown = run(args)
    except RuntimeError as exc:
        log.error(
            "regression run failed after %.1fs: %s",
            time.monotonic() - started_at,
            exc,
        )
        return 1
    _ = Path(args.output).write_text(markdown)
    log.info("wrote PR comment to %s", args.output)
    log.info("regression run complete (elapsed=%.1fs)", time.monotonic() - started_at)
    print(markdown)
    return 0
