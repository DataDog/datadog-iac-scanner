"""Git, worktree, build, and corpus source handling."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path
from types import TracebackType

from .models import CorpusRepo, Variant

log = logging.getLogger("regression")

RELEASE_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
SCANNER_LDFLAGS = "-s -w"


def run_command(
    command: list[str],
    *,
    cwd: str | None = None,
    check: bool = True,
    display_command: list[str] | None = None,
) -> str:
    """Run a command and return stdout, optionally redacting its logged form."""
    log.debug("exec: %s (cwd=%s)", " ".join(display_command or command), cwd)
    process = subprocess.run(
        command, cwd=cwd, text=True, capture_output=True, check=False
    )
    if check and process.returncode != 0:
        shown_command = display_command or command
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(shown_command)}\n"
            + process.stderr
        )
    return process.stdout


def run_git(repo: str, *args: str, check: bool = True) -> str:
    return run_command(["git", "-C", repo, *args], check=check)


def short_sha(repo: str, ref: str) -> str:
    try:
        return run_git(repo, "rev-parse", "--short", ref).strip()
    except RuntimeError:
        return ref


def ensure_fetched(repo: str) -> None:
    """Best-effort fetch of branches and tags needed to resolve baselines."""
    _ = run_git(repo, "fetch", "--quiet", "--tags", "origin", check=False)
    _ = run_git(repo, "fetch", "--quiet", "origin", "main", check=False)


def resolve_latest_release_tag(scanner_repo: str) -> str | None:
    """Return the highest stable vMAJOR.MINOR.PATCH tag, if one exists."""
    tag_output = run_git(scanner_repo, "tag", "--list", "v*", check=False)
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for line in tag_output.splitlines():
        tag = line.strip()
        match = RELEASE_TAG_RE.match(tag)
        if match:
            version = (
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
            )
            candidates.append((version, tag))
    return max(candidates)[1] if candidates else None


class Worktrees:
    """Create and clean up isolated git worktrees for baseline refs."""

    def __init__(self, work_dir: Path):
        self._work_dir: Path = work_dir
        self._created: list[tuple[str, Path]] = []

    def checkout(self, repo: str, ref: str, name: str) -> Path:
        destination = self._work_dir / "worktrees" / name
        if destination.exists():
            return destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        _ = run_git(
            repo, "worktree", "add", "--detach", "--force", str(destination), ref
        )
        self._created.append((repo, destination))
        return destination

    def cleanup(self) -> None:
        for repo, destination in self._created:
            _ = run_git(
                repo,
                "worktree",
                "remove",
                "--force",
                str(destination),
                check=False,
            )
        for repo in {repo for repo, _ in self._created}:
            _ = run_git(repo, "worktree", "prune", check=False)

    def __enter__(self) -> Worktrees:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.cleanup()


class VariantAssets:
    """Materialize and cache scanner binaries and rule paths by git ref."""

    def __init__(
        self,
        scanner_repo: str,
        rules_repo: str,
        work_dir: Path,
        worktrees: Worktrees,
    ) -> None:
        self._scanner_repo: str = scanner_repo
        self._rules_repo: str = rules_repo
        self._work_dir: Path = work_dir
        self._worktrees: Worktrees = worktrees
        self._scanner_binaries: dict[str | None, Path] = {}
        self._rules_paths: dict[str | None, tuple[Path, Path]] = {}

    def prepare(self, variants: list[Variant]) -> None:
        log.info("preparing assets for %d benchmark variants", len(variants))
        for variant in variants:
            _ = self.scanner_binary(variant.scanner_ref)
            _ = self.rules_paths(variant.rules_ref)

    def scanner_binary(self, ref: str | None) -> Path:
        if ref in self._scanner_binaries:
            return self._scanner_binaries[ref]

        source = (
            self._scanner_repo
            if ref is None
            else str(
                self._worktrees.checkout(
                    self._scanner_repo, ref, f"scanner-{filesystem_safe(ref)}"
                )
            )
        )
        binary = (
            self._work_dir / "bin" / f"scanner-{filesystem_safe(ref or 'candidate')}"
        ).resolve()
        binary.parent.mkdir(parents=True, exist_ok=True)

        display_ref = ref or "candidate/PR"
        log.info(
            "scanner build starting (ref=%s, ldflags=%r) -> %s",
            display_ref,
            SCANNER_LDFLAGS,
            binary,
        )
        started_at = time.monotonic()
        environment = os.environ.copy()
        environment["CGO_ENABLED"] = "1"
        process = subprocess.run(
            [
                "go",
                "build",
                "-ldflags",
                SCANNER_LDFLAGS,
                "-o",
                str(binary),
                "./cmd/scanner",
            ],
            cwd=source,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if process.returncode != 0:
            raise RuntimeError(f"scanner build failed (ref={ref}):\n{process.stderr}")

        log.info(
            "scanner build complete (ref=%s, elapsed=%.1fs)",
            display_ref,
            time.monotonic() - started_at,
        )
        self._scanner_binaries[ref] = binary
        return binary

    def rules_paths(self, ref: str | None) -> tuple[Path, Path]:
        if ref in self._rules_paths:
            return self._rules_paths[ref]

        root = (
            Path(self._rules_repo)
            if ref is None
            else self._worktrees.checkout(
                self._rules_repo, ref, f"rules-{filesystem_safe(ref)}"
            )
        )
        paths = (
            (root / "assets" / "queries").resolve(),
            (root / "assets" / "libraries").resolve(),
        )
        for path in paths:
            if not path.is_dir():
                raise RuntimeError(f"rules asset directory not found: {path}")

        self._rules_paths[ref] = paths
        return paths


def filesystem_safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def is_git_checkout(path: Path) -> bool:
    """Accept regular clones and linked worktrees, whose .git entry is a file."""
    return (path / ".git").exists()


def require_repository(path: Path, name: str) -> str:
    """Validate and return a repository checkout path."""
    if not is_git_checkout(path):
        raise RuntimeError(
            f"{name} not found at {path}; place the clone under --repos-dir"
        )
    return str(path)


def resolve_corpus(
    corpus: CorpusRepo,
    *,
    repos_dir: Path,
    work_dir: Path,
    gitretriever_url: str,
    gitretriever_token: str | None,
) -> Path | None:
    """Locate a corpus repository locally or clone it through gitretriever."""
    destination = work_dir / "corpus" / corpus.slug
    search_locations: list[tuple[Path, str]] = [
        (repos_dir / corpus.slug, "using pre-cloned checkout"),
        (repos_dir / corpus.name, "using local checkout"),
        (destination, "reusing"),
    ]

    for path, description in search_locations:
        if is_git_checkout(path):
            log.info("corpus %s: %s %s", corpus.repo, description, path)
            return path

    if not gitretriever_token:
        log.warning(
            "corpus %s not found locally (looked in %s) and no GITRETRIEVER_TOKEN set; skipping",
            corpus.repo,
            repos_dir,
        )
        return None

    destination.parent.mkdir(parents=True, exist_ok=True)
    url = f"{gitretriever_url.rstrip('/')}/{corpus.repo}.git"
    auth_header = f"http.extraHeader=Authorization: Bearer {gitretriever_token}"
    command = ["git", "-c", auth_header, "clone", "--depth", "1"]
    display_command = [
        "git",
        "-c",
        "http.extraHeader=Authorization: Bearer ***",
        "clone",
        "--depth",
        "1",
    ]
    if corpus.ref:
        command += ["--branch", corpus.ref]
        display_command += ["--branch", corpus.ref]
    command += [url, str(destination)]
    display_command += [url, str(destination)]

    log.info("cloning corpus %s from gitretriever", corpus.repo)
    _ = run_command(command, display_command=display_command)
    return destination
