"""Markdown and JSON report rendering."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

from .models import (
    MEM_REGRESSION_PCT,
    TIME_REGRESSION_PCT,
    AggregatedMetrics,
    ComparableMetrics,
    CorpusResult,
    Trigger,
    Variant,
)


class Verdict(str, Enum):
    """Classification of a repo's peak-RSS/finding-count change vs. a baseline."""

    REGRESSED = "regressed"
    IMPROVED = "improved"
    UNCHANGED = "unchanged"


def render_markdown(
    trigger: Trigger,
    variants: list[Variant],
    results: list[CorpusResult],
    public: bool = False,
) -> str:
    candidate = next(variant for variant in variants if variant.is_candidate)
    baselines = [variant for variant in variants if not variant.is_candidate]

    primary_baseline = baselines[0]
    primary_verdicts = _classify_all(trigger, candidate, primary_baseline, results)
    lines = [_headline(primary_verdicts), ""]

    for baseline in baselines:
        verdicts = (
            primary_verdicts
            if baseline is primary_baseline
            else _classify_all(trigger, candidate, baseline, results)
        )
        lines.extend(
            _comparison_section(trigger, candidate, baseline, results, verdicts, public)
        )

    if _has_nondeterministic_findings(candidate, results):
        lines.append(
            "> ⚠️ Finding counts varied across repeated runs on at least one repo (non-deterministic)."
        )
        lines.append("")
    lines.extend(_report_footer(trigger, candidate, primary_baseline))
    return "\n".join(lines)


@dataclass
class _Totals:
    wall_s: float = 0.0
    cpu_s: float = 0.0
    peak_rss_mib: float = 0.0
    findings: int = 0

    def add(self, metrics: ComparableMetrics) -> None:
        self.wall_s += metrics.wall_s
        self.cpu_s += metrics.cpu_s
        self.peak_rss_mib = max(self.peak_rss_mib, metrics.peak_rss_mib)
        self.findings += metrics.findings


def _classify(
    trigger: Trigger, candidate: ComparableMetrics, baseline: ComparableMetrics
) -> Verdict:
    if trigger == Trigger.SCANNER and candidate.findings != baseline.findings:
        return Verdict.REGRESSED
    if baseline.peak_rss_mib <= 0:
        return Verdict.UNCHANGED
    percent_change = (
        (candidate.peak_rss_mib - baseline.peak_rss_mib) / baseline.peak_rss_mib * 100.0
    )
    if percent_change > MEM_REGRESSION_PCT:
        return Verdict.REGRESSED
    if percent_change < -MEM_REGRESSION_PCT:
        return Verdict.IMPROVED
    return Verdict.UNCHANGED


def _classify_all(
    trigger: Trigger,
    candidate: Variant,
    baseline: Variant,
    results: list[CorpusResult],
) -> dict[str, Verdict]:
    verdicts: dict[str, Verdict] = {}
    for result in results:
        candidate_metrics = result.by_variant.get(candidate.key)
        baseline_metrics = result.by_variant.get(baseline.key)
        if candidate_metrics is None or baseline_metrics is None:
            verdicts[result.repo] = Verdict.REGRESSED
            continue
        verdicts[result.repo] = _classify(trigger, candidate_metrics, baseline_metrics)
    return verdicts


def _headline(verdicts: dict[str, Verdict]) -> str:
    total = len(verdicts)
    repo_label = "repo" if total == 1 else "repos"
    regressed = sum(1 for verdict in verdicts.values() if verdict == Verdict.REGRESSED)
    improved = sum(1 for verdict in verdicts.values() if verdict == Verdict.IMPROVED)
    unchanged = total - regressed - improved
    if regressed:
        verb = "shows" if regressed == 1 else "show"
        scope = f"{regressed} of {total}" if total > 1 else str(regressed)
        headline = (
            f"### ❌ {scope} {repo_label} {verb} a regression "
            + "(peak RSS and/or finding-count change)"
        )
    elif improved:
        headline = f"### ⚡ No regressions detected across {total} {repo_label} — some improved"
    else:
        headline = f"### ✅ No regressions detected across {total} {repo_label}"
    counts = (
        f"❌ {regressed} regressed · ⚡ {improved} improved · ✅ {unchanged} unchanged"
    )
    return headline + "\n" + counts


def _comparison_section(
    trigger: Trigger,
    candidate: Variant,
    baseline: Variant,
    results: list[CorpusResult],
    verdicts: dict[str, Verdict],
    public: bool,
) -> list[str]:
    header = [
        f"### Compared with `{baseline.name}`",
        "<sub>"
        + f"Scanner <code>{baseline.scanner_display}</code> · "
        + f"Rules <code>{baseline.rules_display}</code>"
        + "</sub>",
        "",
    ]
    findings_tooltip = (
        "Finding-count change from baseline, as a percentage"
        if public
        else "Candidate finding count and change from baseline"
    )
    table_header = [
        f'|  | Repository | <span title="{findings_tooltip}">Findings</span> | '
        + '<span title="Median peak resident memory; changes beyond the threshold are flagged">Peak RSS</span> | '
        + '<span title="Best observed wall time; advisory only">Wall</span> | '
        + '<span title="Best observed CPU time; advisory only">CPU</span> |',
        "| --- | --- | --- | --- | --- | --- |",
    ]
    candidate_totals = _Totals()
    baseline_totals = _Totals()
    flagged_rows: list[str] = []
    unchanged_rows: list[str] = []

    for result in results:
        candidate_metrics = result.by_variant.get(candidate.key)
        baseline_metrics = result.by_variant.get(baseline.key)
        verdict = verdicts[result.repo]
        repo_label = f"`{result.display(public)}`"
        if candidate_metrics is None or baseline_metrics is None:
            flagged_rows.append(
                f"| {_VERDICT_ICON[verdict]} | {repo_label} | ❌ scan failed | – | – | – |"
            )
            continue

        candidate_totals.add(candidate_metrics)
        baseline_totals.add(baseline_metrics)
        row = _comparison_row(
            verdict,
            repo_label,
            trigger,
            candidate_metrics,
            baseline_metrics,
            nondeterministic=candidate_metrics.findings_nondeterministic,
            public=public,
        )
        if verdict == Verdict.UNCHANGED:
            unchanged_rows.append(row)
        else:
            flagged_rows.append(row)

    total_row = _comparison_row(
        None,
        "**total**",
        trigger,
        candidate_totals,
        baseline_totals,
        maximum_memory=True,
        public=public,
    )

    lines = [*header]
    if flagged_rows:
        lines.extend([*table_header, *flagged_rows])
    if unchanged_rows:
        if not flagged_rows:
            lines.extend(table_header)
        else:
            lines.append("")
            unchanged_label = f"{len(unchanged_rows)} unchanged repo"
            unchanged_label += "s" if len(unchanged_rows) != 1 else ""
            lines.append("<details>")
            lines.append(f"<summary>{unchanged_label}</summary>")
            lines.append("")
            lines.extend(table_header)
        lines.extend(unchanged_rows)
        if flagged_rows:
            lines.append("")
            lines.append("</details>")
    if not flagged_rows and not unchanged_rows:
        lines.extend(table_header)
    lines.append(total_row)
    lines.append("")
    return lines


_VERDICT_ICON = {
    Verdict.REGRESSED: "❌",
    Verdict.IMPROVED: "⚡",
    Verdict.UNCHANGED: "✅",
}


def _comparison_row(
    verdict: Verdict | None,
    label: str,
    trigger: Trigger,
    candidate: ComparableMetrics,
    baseline: ComparableMetrics,
    *,
    nondeterministic: bool = False,
    maximum_memory: bool = False,
    public: bool = False,
) -> str:
    icon = "" if verdict is None else _VERDICT_ICON[verdict]
    return "| {icon} | {label} | {findings} | {memory} | {wall} | {cpu} |".format(
        icon=icon,
        label=label,
        findings=_int_delta(
            candidate.findings,
            baseline.findings,
            trigger,
            nondeterministic=nondeterministic,
            public=public,
        ),
        memory=_delta_cell(
            candidate.peak_rss_mib,
            baseline.peak_rss_mib,
            "MiB",
            MEM_REGRESSION_PCT,
            show_max_prefix=maximum_memory,
        ),
        wall=_delta_cell(
            candidate.wall_s,
            baseline.wall_s,
            "s",
            TIME_REGRESSION_PCT,
            advisory=True,
        ),
        cpu=_delta_cell(
            candidate.cpu_s,
            baseline.cpu_s,
            "s",
            TIME_REGRESSION_PCT,
            advisory=True,
        ),
    )


def _report_footer(trigger: Trigger, candidate: Variant, baseline: Variant) -> list[str]:
    if trigger == Trigger.SCANNER:
        findings_note = "A finding-count delta indicates a scanner behaviour change and should be explained."
    else:
        findings_note = "Finding-count changes are expected for default-rules changes."
    return [
        f"Comparing candidate <code>{candidate.scanner_display}</code> with "
        + f"<code>{baseline.name}</code> <code>{baseline.scanner_display}</code>",
        "",
        "<details>",
        "<summary>How to read this report</summary>",
        "",
        f"• {findings_note}<br />",
        f"• Peak RSS changes beyond {MEM_REGRESSION_PCT:.0f}% are flagged; lower is better.<br />",
        "• Wall and CPU use the best observed run and are advisory; small changes are usually noise.<br />",
        "This comment is updated automatically when new benchmark data arrives.",
        "</details>",
    ]


def _has_nondeterministic_findings(
    candidate: Variant, results: list[CorpusResult]
) -> bool:
    for result in results:
        metrics = result.by_variant.get(candidate.key)
        if metrics is not None and metrics.findings_nondeterministic:
            return True
    return False


def _int_delta(
    candidate: int,
    baseline: int,
    trigger: Trigger,
    *,
    nondeterministic: bool = False,
    public: bool = False,
) -> str:
    difference = candidate - baseline
    if public:
        body = _findings_percent(candidate, baseline, trigger)
    elif difference == 0:
        body = f"{candidate}"
    else:
        marker = "❌ " if trigger == Trigger.SCANNER else ""
        body = f"{marker}{candidate} ({difference:+d})"
    if nondeterministic:
        body += " ⚠️nondet"
    return body


def _findings_percent(candidate: int, baseline: int, trigger: Trigger) -> str:
    """Finding-count change as a percentage only — no absolute counts.

    Used in public mode, where disclosing exact violation counts for internal
    repositories is not acceptable but relative movement still needs surfacing.
    """
    if candidate == baseline:
        return "no change"
    marker = "❌ " if trigger == Trigger.SCANNER else ""
    if baseline <= 0:
        # No baseline findings to divide by; a percentage would be meaningless.
        return f"{marker}new findings"
    percent_change = (candidate - baseline) / baseline * 100.0
    return f"{marker}{percent_change:+.1f}%"


def _delta_cell(
    candidate: float,
    baseline: float,
    unit: str,
    warn_pct: float,
    show_max_prefix: bool = False,
    advisory: bool = False,
) -> str:
    formatted_value = _format_metric(candidate, unit)
    prefix = "max " if show_max_prefix else ""
    if baseline <= 0:
        return f"{prefix}{formatted_value}"
    percent_change = (candidate - baseline) / baseline * 100.0
    if advisory or -warn_pct <= percent_change <= warn_pct:
        marker = ""
    elif percent_change > warn_pct:
        marker = "❌ "
    else:
        marker = "⚡ "
    return f"{marker}{prefix}{formatted_value} ({percent_change:+.1f}%)"


def _format_metric(value: float, unit: str) -> str:
    if unit == "MiB":
        return f"{value:.0f} MiB"
    return f"{value:.2f} {unit}"


def json_summary(variants: list[Variant], results: list[CorpusResult]) -> str:
    return json.dumps(
        {
            "variants": [_variant_json(variant) for variant in variants],
            "results": [_corpus_result_json(result) for result in results],
        },
        indent=2,
    )


def _variant_json(variant: Variant) -> dict[str, object]:
    return {
        "label": variant.label,
        "scanner": variant.scanner_display,
        "rules": variant.rules_display,
        "candidate": variant.is_candidate,
    }


def _corpus_result_json(result: CorpusResult) -> dict[str, object]:
    variants: dict[str, object] = {
        label: None if aggregate is None else _aggregate_json(aggregate)
        for label, aggregate in result.by_variant.items()
    }
    return {"repo": result.repo, "variants": variants}


def _aggregate_json(aggregate: AggregatedMetrics) -> dict[str, object]:
    return {
        "findings": aggregate.findings,
        "findings_by_severity": aggregate.findings_by_severity,
        "wall_s": round(aggregate.wall_s, 3),
        "cpu_s": round(aggregate.cpu_s, 3),
        "peak_rss_mib": round(aggregate.peak_rss_mib, 1),
        "files": aggregate.files,
        "rules": aggregate.rules,
    }
