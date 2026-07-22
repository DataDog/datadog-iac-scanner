"""Scan measurement, aggregation, and benchmark orchestration."""

from __future__ import annotations

import json
import logging
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .models import (
    AggregatedMetrics,
    CliArgs,
    CorpusRepo,
    CorpusResult,
    RunMetrics,
    SCANNER_REPO,
    Trigger,
    Variant,
)
from .report import json_summary, render_markdown
from .sources import (
    VariantAssets,
    Worktrees,
    ensure_fetched,
    filesystem_safe,
    is_git_checkout,
    require_repository,
    resolve_corpus,
    resolve_latest_release_tag,
    short_sha,
)

log = logging.getLogger("regression")


def measure_scan(
    scanner_binary: Path,
    corpus_dir: Path,
    queries: Path | None,
    libraries: Path | None,
    platforms: list[str],
    temp_dir: Path,
) -> RunMetrics:
    """Run one scan under rusage measurement and parse its metadata JSON.

    When ``queries``/``libraries`` are None the scanner is invoked without local
    rule paths, so it fetches the deployed default ruleset from the Datadog
    backend at runtime.
    """
    metadata_path = temp_dir / "meta.json"
    if metadata_path.exists():
        metadata_path.unlink()
    log_path = temp_dir / "scan.log"

    command = [
        str(scanner_binary),
        "scan",
        "--path",
        str(corpus_dir),
        "--metadata-path",
        str(metadata_path),
    ]
    if queries is not None:
        command += ["--queries-path", str(queries)]
    if libraries is not None:
        command += ["--libraries-path", str(libraries)]
    for platform in platforms:
        command += ["--type", platform]

    exit_code, wall_s, cpu_s, peak_rss_mib = _run_measured(
        command, str(corpus_dir), log_path
    )
    if not metadata_path.exists():
        raise RuntimeError(
            f"scan produced no metadata (exit {exit_code}); last output:\n"
            + _tail(log_path)
        )

    metadata = _read_json_object(metadata_path)
    stats = _object_dict(metadata.get("Stats", {}), "Stats")
    breakdowns = _object_dict(
        stats.get("ViolationBreakdowns") or {}, "Stats.ViolationBreakdowns"
    )
    return RunMetrics(
        wall_s=wall_s,
        cpu_s=cpu_s,
        peak_rss_mib=peak_rss_mib,
        findings=_as_int(stats.get("Violations", 0), "Stats.Violations"),
        findings_by_severity=_flatten_severity(breakdowns),
        files=_as_int(stats.get("Files", 0), "Stats.Files"),
        rules=_as_int(stats.get("Rules", 0), "Stats.Rules"),
    )


def _run_measured(
    command: list[str], cwd: str, log_path: Path
) -> tuple[int, float, float, float]:
    """Fork/exec a scan and return exit code, wall time, CPU time, and peak RSS."""
    environment = os.environ.copy()
    start = time.monotonic()
    pid = os.fork()
    if pid == 0:
        try:
            os.chdir(cwd)
            output_fd = os.open(
                str(log_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644
            )
            _ = os.dup2(output_fd, 1)
            _ = os.dup2(output_fd, 2)
            os.close(output_fd)
            os.execvpe(command[0], command, environment)
        except Exception:  # noqa: BLE001 - last resort in the forked child
            os._exit(127)

    _, status, usage = os.wait4(pid, 0)
    wall_s = time.monotonic() - start
    exit_code = os.waitstatus_to_exitcode(status)
    peak_rss_mib = (
        usage.ru_maxrss / 1024
        if sys.platform != "darwin"
        else usage.ru_maxrss / (1024 * 1024)
    )
    cpu_s = usage.ru_utime + usage.ru_stime
    return exit_code, wall_s, cpu_s, peak_rss_mib


def _read_json_object(path: Path) -> dict[str, object]:
    value = cast(object, json.loads(path.read_text()))
    return _object_dict(value, str(path))


def _object_dict(value: object, field_name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError(f"{field_name} must be a JSON object")
    return cast(dict[str, object], value)


def _as_int(value: object, field_name: str) -> int:
    if isinstance(value, (int, float, str)):
        return int(value)
    raise RuntimeError(f"{field_name} must be numeric")


def _flatten_severity(breakdowns: dict[str, object]) -> dict[str, int]:
    """Sum ViolationBreakdowns category counts by severity."""
    flattened: dict[str, int] = {}
    for severity, categories_or_count in breakdowns.items():
        if isinstance(categories_or_count, dict):
            categories = cast(dict[str, object], categories_or_count)
            flattened[severity] = sum(
                _as_int(value, f"ViolationBreakdowns.{severity}")
                for value in categories.values()
            )
        else:
            flattened[severity] = _as_int(
                categories_or_count, f"ViolationBreakdowns.{severity}"
            )
    return flattened


def _tail(path: Path, line_count: int = 40) -> str:
    try:
        return "\n".join(path.read_text().splitlines()[-line_count:])
    except OSError:
        return "(no output captured)"


def aggregate_runs(runs: list[RunMetrics]) -> AggregatedMetrics:
    """Aggregate repeated runs and flag non-deterministic finding counts."""
    finding_counts = {run.findings for run in runs}
    return AggregatedMetrics(
        wall_s=min(run.wall_s for run in runs),
        cpu_s=min(run.cpu_s for run in runs),
        peak_rss_mib=statistics.median(run.peak_rss_mib for run in runs),
        findings=statistics.median_low(run.findings for run in runs),
        findings_by_severity=runs[0].findings_by_severity,
        files=runs[0].files,
        rules=runs[0].rules,
        findings_nondeterministic=len(finding_counts) > 1,
    )


def build_variants(trigger: Trigger, scanner_repo: str) -> list[Variant]:
    """Build the candidate-first list of scanner/rules combinations."""
    release_tag = resolve_latest_release_tag(scanner_repo)
    if trigger == Trigger.SCANNER:
        variants = [
            Variant(
                key="candidate",
                name="this PR",
                scanner_ref=None,
                rules_ref=None,
                is_candidate=True,
            ),
            Variant(
                key="baseline-main",
                name="main",
                scanner_ref="origin/main",
                rules_ref=None,
            ),
        ]
        if release_tag:
            variants.append(
                Variant(
                    key=f"baseline-{release_tag}",
                    name=release_tag,
                    scanner_ref=release_tag,
                    rules_ref=None,
                )
            )
        else:
            log.warning(
                "no semver release tag found; skipping the released-tag baseline"
            )
        return variants

    scanner_ref = release_tag or "origin/main"
    return [
        Variant(
            key="candidate",
            name="this PR",
            scanner_ref=scanner_ref,
            rules_ref=None,
            is_candidate=True,
        ),
        Variant(
            key="baseline-main",
            name="main",
            scanner_ref=scanner_ref,
            rules_ref="origin/main",
        ),
    ]


@dataclass(frozen=True)
class BenchmarkContext:
    variants: list[Variant]
    assets: VariantAssets
    work_dir: Path
    platforms: list[str]
    runs: int
    warmup: bool


def run(args: CliArgs) -> str:
    repos_dir = Path(args.repos_dir).expanduser().resolve()
    scanner_repo = require_repository(SCANNER_REPO, "datadog-iac-scanner")
    rules_checkout = repos_dir / "datadog-iac-scanner-default-rules"
    use_remote_rules = args.remote_rules or not is_git_checkout(rules_checkout)
    if use_remote_rules and args.trigger == Trigger.RULES:
        raise RuntimeError(
            "--trigger rules requires a local default-rules "
            + f"checkout under {repos_dir} (looked at {rules_checkout}); remote "
            + "rules are held fixed and cannot vary the ruleset per variant"
        )
    if use_remote_rules:
        log.info(
            "using remote rules: the scanner will fetch the deployed default "
            + "ruleset from the Datadog backend at runtime (no rules checkout %s)",
            "requested" if args.remote_rules else "found",
        )
        rules_repo = None
    else:
        rules_repo = require_repository(
            rules_checkout, "datadog-iac-scanner-default-rules"
        )
    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    ensure_fetched(scanner_repo)
    if args.trigger == Trigger.RULES and rules_repo is not None:
        ensure_fetched(rules_repo)

    corpus = load_corpus(Path(args.corpus_config))
    if not corpus:
        raise RuntimeError(f"no corpus repos configured in {args.corpus_config}")
    if args.public:
        _require_public_names(corpus, args.corpus_config)

    variants = build_variants(args.trigger, scanner_repo)
    _set_variant_display_names(variants, args.trigger, scanner_repo, rules_repo)
    measured_scans_per_repo = len(variants) * args.runs
    log.info(
        "benchmark plan: %d configured repos; %d variants x %d runs = "
        + "%d measured scans per available repo; warmup=%s",
        len(corpus),
        len(variants),
        args.runs,
        measured_scans_per_repo,
        "enabled" if args.warmup else "disabled",
    )
    log.info("benchmark variants: %s", ", ".join(v.label for v in variants))

    results: list[CorpusResult] = []
    with Worktrees(work_dir) as worktrees:
        assets = VariantAssets(scanner_repo, rules_repo, work_dir, worktrees)
        assets.prepare(variants)
        context = BenchmarkContext(
            variants=variants,
            assets=assets,
            work_dir=work_dir,
            platforms=_parse_platforms(args.platforms),
            runs=args.runs,
            warmup=args.warmup,
        )
        for repo_index, corpus_repo in enumerate(corpus, start=1):
            log.info(
                "corpus %d/%d: resolving %s", repo_index, len(corpus), corpus_repo.repo
            )
            repository_path = resolve_corpus(
                corpus_repo,
                repos_dir=repos_dir,
                work_dir=work_dir,
                gitretriever_url=args.gitretriever_url,
                gitretriever_token=args.gitretriever_token,
            )
            if repository_path is not None:
                results.append(
                    _benchmark_repository(corpus_repo, repository_path, context)
                )

    if not results:
        raise RuntimeError(
            "no corpus repos were available to scan (none found locally and none "
            + "cloned); check --corpus-config, --repos-dir, or set GITRETRIEVER_TOKEN"
        )

    markdown = render_markdown(args.trigger, variants, results, args.public)
    if args.json_output:
        _ = Path(args.json_output).write_text(json_summary(variants, results))
    return markdown


def _set_variant_display_names(
    variants: list[Variant],
    trigger: Trigger,
    scanner_repo: str,
    rules_repo: str | None,
) -> None:
    for variant in variants:
        variant.scanner_display = (
            "PR"
            if variant.is_candidate and trigger == Trigger.SCANNER
            else short_sha(scanner_repo, variant.scanner_ref or "HEAD")
        )
        if variant.is_candidate and trigger == Trigger.RULES:
            variant.rules_display = "PR"
        elif rules_repo is None:
            variant.rules_display = "remote"
        else:
            variant.rules_display = short_sha(rules_repo, variant.rules_ref or "HEAD")


def _parse_platforms(value: str) -> list[str]:
    return [platform.strip() for platform in value.split(",") if platform.strip()]


def _benchmark_repository(
    corpus_repo: CorpusRepo, repository_path: Path, context: BenchmarkContext
) -> CorpusResult:
    started_at = time.monotonic()
    log.info(
        "%s: benchmark starting (%d measured scans%s)",
        corpus_repo.repo,
        len(context.variants) * context.runs,
        " plus warmup" if context.warmup else "",
    )
    if context.warmup:
        _warm_repository(corpus_repo, repository_path, context)

    samples, failed_variants = _collect_samples(corpus_repo, repository_path, context)
    result = _aggregate_repository(
        corpus_repo, context.variants, samples, failed_variants
    )
    log.info(
        "%s: benchmark complete (elapsed=%.1fs)",
        corpus_repo.repo,
        time.monotonic() - started_at,
    )
    return result


def _warm_repository(
    corpus_repo: CorpusRepo, repository_path: Path, context: BenchmarkContext
) -> None:
    candidate = context.variants[0]
    temp_dir = _scan_temp_dir(context.work_dir, corpus_repo, "warmup")
    queries, libraries = context.assets.rules_paths(candidate.rules_ref) or (None, None)
    log.info("%s: warmup scan starting (variant=%s)", corpus_repo.repo, candidate.label)
    started_at = time.monotonic()
    try:
        metrics = measure_scan(
            context.assets.scanner_binary(candidate.scanner_ref),
            repository_path,
            queries,
            libraries,
            context.platforms,
            temp_dir,
        )
        log.info(
            "%s: warmup scan complete (elapsed=%.1fs, wall=%.2fs, findings=%d; discarded)",
            corpus_repo.repo,
            time.monotonic() - started_at,
            metrics.wall_s,
            metrics.findings,
        )
    except RuntimeError as exc:
        log.warning(
            "%s: warmup scan failed after %.1fs (ignored): %s",
            corpus_repo.repo,
            time.monotonic() - started_at,
            exc,
        )


def _collect_samples(
    corpus_repo: CorpusRepo, repository_path: Path, context: BenchmarkContext
) -> tuple[dict[str, list[RunMetrics]], set[str]]:
    """Measure variants in rotating order to reduce positional timing bias."""
    samples: dict[str, list[RunMetrics]] = {
        variant.key: [] for variant in context.variants
    }
    failed_variants: set[str] = set()
    variant_count = len(context.variants)
    total_scans = context.runs * variant_count

    for run_index in range(context.runs):
        offset = run_index % variant_count
        run_order = context.variants[offset:] + context.variants[:offset]
        for position, variant in enumerate(run_order):
            scan_index = run_index * variant_count + position + 1
            if variant.key in failed_variants:
                log.info(
                    "%s: scan %d/%d skipped (round %d/%d, variant=%s failed earlier)",
                    corpus_repo.repo,
                    scan_index,
                    total_scans,
                    run_index + 1,
                    context.runs,
                    variant.label,
                )
                continue
            sample = _measure_variant(
                corpus_repo,
                repository_path,
                variant,
                context,
                scan_index=scan_index,
                total_scans=total_scans,
                round_number=run_index + 1,
            )
            if sample is None:
                failed_variants.add(variant.key)
            else:
                samples[variant.key].append(sample)

    return samples, failed_variants


def _measure_variant(
    corpus_repo: CorpusRepo,
    repository_path: Path,
    variant: Variant,
    context: BenchmarkContext,
    *,
    scan_index: int,
    total_scans: int,
    round_number: int,
) -> RunMetrics | None:
    temp_dir = _scan_temp_dir(
        context.work_dir, corpus_repo, filesystem_safe(variant.key)
    )
    log.info(
        "%s: scan %d/%d starting (round %d/%d, variant=%s)",
        corpus_repo.repo,
        scan_index,
        total_scans,
        round_number,
        context.runs,
        variant.label,
    )
    started_at = time.monotonic()
    queries, libraries = context.assets.rules_paths(variant.rules_ref) or (None, None)
    try:
        metrics = measure_scan(
            context.assets.scanner_binary(variant.scanner_ref),
            repository_path,
            queries,
            libraries,
            context.platforms,
            temp_dir,
        )
    except RuntimeError as exc:
        log.error(
            "%s: scan %d/%d failed after %.1fs (variant=%s): %s",
            corpus_repo.repo,
            scan_index,
            total_scans,
            time.monotonic() - started_at,
            variant.label,
            exc,
        )
        return None
    log.info(
        "%s: scan %d/%d complete (variant=%s, elapsed=%.1fs, wall=%.2fs, "
        + "cpu=%.2fs, peak=%.0fMiB, findings=%d)",
        corpus_repo.repo,
        scan_index,
        total_scans,
        variant.label,
        time.monotonic() - started_at,
        metrics.wall_s,
        metrics.cpu_s,
        metrics.peak_rss_mib,
        metrics.findings,
    )
    return metrics


def _scan_temp_dir(work_dir: Path, corpus_repo: CorpusRepo, suffix: str) -> Path:
    temp_dir = work_dir / "scan-tmp" / f"{corpus_repo.slug}__{suffix}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    return temp_dir


def _aggregate_repository(
    corpus_repo: CorpusRepo,
    variants: list[Variant],
    samples: dict[str, list[RunMetrics]],
    failed_variants: set[str],
) -> CorpusResult:
    result = CorpusResult(repo=corpus_repo.repo, public_name=corpus_repo.public_name)
    for variant in variants:
        variant_samples = samples[variant.key]
        if variant.key in failed_variants or not variant_samples:
            result.by_variant[variant.key] = None
            continue

        aggregate = aggregate_runs(variant_samples)
        result.by_variant[variant.key] = aggregate
        log.info(
            "%s: summary (variant=%s, findings=%d, best wall=%.2fs, "
            + "best cpu=%.2fs, median peak=%.0fMiB)",
            corpus_repo.repo,
            variant.label,
            aggregate.findings,
            aggregate.wall_s,
            aggregate.cpu_s,
            aggregate.peak_rss_mib,
        )
    return result


def load_corpus(path: Path) -> list[CorpusRepo]:
    data = _read_json_object(path)
    corpus_value = data.get("corpus", [])
    if not isinstance(corpus_value, list):
        raise RuntimeError(f"{path}: corpus must be a JSON array")

    repositories: list[CorpusRepo] = []
    for entry in cast(list[object], corpus_value):
        if isinstance(entry, str):
            repositories.append(CorpusRepo(repo=entry))
            continue

        fields = _object_dict(entry, f"{path}: corpus entry")
        repo = fields.get("repo")
        ref = fields.get("ref", "")
        public_name = fields.get("public_name", "")
        if (
            not isinstance(repo, str)
            or not isinstance(ref, str)
            or not isinstance(public_name, str)
        ):
            raise RuntimeError(
                f"{path}: corpus repo, ref and public_name must be strings"
            )
        repositories.append(CorpusRepo(repo=repo, ref=ref, public_name=public_name))
    return repositories


def _require_public_names(corpus: list[CorpusRepo], corpus_config: str) -> None:
    """Fail loudly if public mode would leak a repo lacking a public_name."""
    missing = [repo.repo for repo in corpus if not repo.public_name]
    if missing:
        raise RuntimeError(
            "public mode requires a public_name for every corpus repo; missing "
            + f"for: {', '.join(missing)} (add it in {corpus_config})"
        )
