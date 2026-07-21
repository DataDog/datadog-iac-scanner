"""Shared configuration and data models for regression benchmarks."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

TIME_REGRESSION_PCT = 10.0
MEM_REGRESSION_PCT = 10.0
DEFAULT_RUNS = 3
DEFAULT_GITRETRIEVER_URL = "https://gitretriever.us1.ddbuild.io"
DEFAULT_WORK_DIR = "./.regression-work"
DEFAULT_OUTPUT = "regression-comment.md"
SCANNER_REPO = Path(__file__).resolve().parents[2]
DEFAULT_REPOS_DIR = str(SCANNER_REPO.parent)
DEFAULT_CORPUS_CONFIG = str(SCANNER_REPO / "regression_detector" / "corpus.json")


class Trigger(str, Enum):
    """Which repo's PR triggered the benchmark run."""

    SCANNER = "scanner"
    RULES = "rules"

    def __str__(self) -> str:  # pyright: ignore[reportImplicitOverride]
        return self.value


@dataclass
class Variant:
    """One scanner/rules combination used to scan the corpus.

    ``key`` is the stable identifier used to look up per-variant results;
    ``name`` is the display text (e.g. "this PR", "main", "v1.2.3"), kept
    separate so report rendering never needs to parse it back out of a
    formatted label.
    """

    key: str
    name: str
    # None means "use the repository as currently checked out" (i.e. the
    # candidate/PR working tree) rather than materializing a worktree for an
    # explicit ref; call sites render this as "HEAD", "candidate", or "PR"
    # as appropriate for git lookups, file naming, or display respectively.
    scanner_ref: str | None
    rules_ref: str | None
    is_candidate: bool = False
    scanner_display: str = ""
    rules_display: str = ""

    @property
    def label(self) -> str:
        """Human-readable heading used in logs and section titles."""
        return (
            f"candidate ({self.name})"
            if self.is_candidate
            else f"baseline: {self.name}"
        )


@dataclass
class RunMetrics:
    """Measurements from a single scan invocation."""

    wall_s: float
    cpu_s: float
    peak_rss_mib: float
    findings: int
    findings_by_severity: dict[str, int]
    files: int
    rules: int


@dataclass
class AggregatedMetrics(RunMetrics):
    """Metrics aggregated across runs for a variant and corpus repository."""

    findings_nondeterministic: bool = False


@dataclass
class CorpusRepo:
    repo: str
    ref: str = ""
    # Anonymized label shown instead of ``repo`` in public mode
    public_name: str = ""

    @property
    def slug(self) -> str:
        return self.repo.replace("/", "__")

    @property
    def name(self) -> str:
        """Repository name without the organization."""
        return self.repo.split("/")[-1]


# Fallback label used when a public run has no configured public_name; kept
# generic so it can never leak the real repository identity.
REDACTED_REPO = "hidden"


@dataclass
class CorpusResult:
    repo: str
    public_name: str = ""
    by_variant: dict[str, AggregatedMetrics | None] = field(default_factory=dict)

    def display(self, public: bool) -> str:
        """Repository label to show in the report for the given visibility."""
        if not public:
            return self.repo
        return self.public_name or REDACTED_REPO


class ComparableMetrics(Protocol):
    """Metrics shared by per-repository aggregates and report totals."""

    wall_s: float
    cpu_s: float
    peak_rss_mib: float
    findings: int


class CliArgs(argparse.Namespace):
    """Typed namespace populated by argparse."""

    trigger: Trigger
    repos_dir: str
    corpus_config: str
    work_dir: str
    runs: int
    warmup: bool
    platforms: str
    gitretriever_url: str
    gitretriever_token: str | None
    output: str
    json_output: str
    public: bool
    verbose: bool

    def __init__(self) -> None:
        super().__init__()
        self.trigger = Trigger.SCANNER
        self.repos_dir = DEFAULT_REPOS_DIR
        self.corpus_config = DEFAULT_CORPUS_CONFIG
        self.work_dir = DEFAULT_WORK_DIR
        self.runs = DEFAULT_RUNS
        self.warmup = True
        self.platforms = ""
        self.gitretriever_url = DEFAULT_GITRETRIEVER_URL
        self.gitretriever_token = os.environ.get("GITRETRIEVER_TOKEN")
        self.output = DEFAULT_OUTPUT
        self.json_output = ""
        self.public = bool(os.environ.get("CI"))
        self.verbose = False
