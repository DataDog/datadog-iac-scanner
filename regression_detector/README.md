# Performance regression benchmark

`run.py` scans a corpus of repositories with a **candidate** build and one or more **baselines**, measures wall time / CPU / peak memory / finding counts, and renders a Markdown PR comment with the deltas. It is the shared entry point for the regression gate in **both** the scanner and the default-rules CI pipelines; the reuse unit is this CLI, not the pipeline YAML.

## What it compares

| Trigger (`--trigger`) | Variable | Held fixed | Baselines |
| --- | --- | --- | --- |
| `scanner` | scanner binary | rules (local `main`, or the deployed ruleset with `--remote-rules`) | scanner `main` **and** latest release tag `vX.Y.Z` |
| `rules` | rules (`assets/`) | scanner (latest release tag) | rules `main` |

Release tags are semver `vX.Y.Z` only; pre-releases (`-alpha`, etc.) are ignored. The candidate is always the PR working tree as checked out; baselines are materialised in isolated git worktrees, so the checked-out tree is never mutated.

## What the pipeline must provide

- The **datadog-iac-scanner** checkout containing this entrypoint, with tags + `origin/main` fetchable (the script does a best-effort fetch).
- A **datadog-iac-scanner-default-rules** clone under `--repos-dir` — **unless** running with `--remote-rules` (see below), in which case no rules clone is needed.
- The `go` toolchain (to build the scanner variants; `CGO_ENABLED=1`).
- Corpus repos: either pre-cloned under `--repos-dir`, or reachable via gitretriever with a Bearer token in `$GITRETRIEVER_TOKEN` (in GitLab CI, mint one with an ID token: `id_tokens: {GITRETRIEVER_ID_TOKEN: {aud: codesync}}`).

## Local usage (no CI, no token)

The scanner checkout is discovered from the entrypoint. Other clones default to the scanner repository's parent directory, so a developer can just run:

```bash
# benchmark this scanner working tree vs main + latest tag
python regression_detector/run.py --trigger scanner

# benchmark sibling default-rules working-tree changes vs main
python regression_detector/run.py --trigger rules
```

The candidate is your **working tree** (uncommitted changes included). Use `--repos-dir` when rules or corpus clones are not siblings of the scanner. Corpus resolution order: `<repos-dir>/<org__name>` → `<repos-dir>/<name>` → previous clone in `--work-dir` → clone from gitretriever.

## CI usage

The scanner trigger passes `--remote-rules`: the scanner fetches the deployed default ruleset from the Datadog backend at runtime (`api.<DD_SITE>` — default `datadoghq.com`), so no local rules checkout is needed. Remote rules are held fixed across every variant, so `--remote-rules` is scanner-only; `--trigger rules` still requires a local checkout because it varies the ruleset per variant. When no local rules checkout is found under `--repos-dir`, remote rules are used automatically.

```bash
# scanner PR
python regression_detector/run.py \
  --trigger scanner \
  --remote-rules \
  --repos-dir /work \
  --output       regression-comment.md

# rules PR (scanner cloned alongside)
python /work/datadog-iac-scanner/regression_detector/run.py \
  --trigger rules \
  --repos-dir "$(dirname "$CI_PROJECT_DIR")" \
  --output       regression-comment.md
```

Then hand `regression-comment.md` to the pr-commenter service as the comment `message` (see the repo-level DDCI onboarding notes for the `pr-commenter` call).

Options worth knowing: `--runs N` (repetitions per variant/repo; default 3), `--platforms terraform,kubernetes`, `--json-output summary.json` (machine-readable), `--work-dir` (scratch dir), `-v` (debug logging).

## Public mode

The rendered comment is posted on a **public** PR, so it must not disclose internal detail. Public mode redacts it:

- **Repository identities** are replaced by each corpus entry's `public_name` (see `corpus.json`) instead of the real `org/name`.
- **Finding counts** are shown as a **percentage delta only** — never the absolute number (e.g. `❌ +20.0%` rather than `120 (+20)`). Peak RSS / wall / CPU are unchanged.

Public mode is **auto-enabled in CI** (whenever `$CI` is set) and off for local runs, so a developer sees the raw repo names and exact counts while the CI-posted comment stays redacted. Override the auto-detection with `--public` / `--no-public`.

When public mode is on, every corpus repo **must** define a `public_name`; the run fails fast otherwise rather than risk leaking a real name. The `--json-output` summary is machine-readable and internal-only, so it is left un-redacted.

## How measurements are taken

Each scan is run via `os.fork`/`os.wait4`, so peak RSS (`ru_maxrss`) and CPU (`ru_utime + ru_stime`) are scoped to that single scan process, with no third-party dependency (e.g. psutil) and no `pip install` step. Wall time is `monotonic`. Finding counts, files, and rules come from the scanner's `--metadata-path` JSON (`Stats.*`). A scan is considered successful when it produces that metadata file; the scanner's non-zero severity exit codes (20 to 60) are **not** treated as failures.

## Measurement fairness (run ordering)

Wall/CPU/memory are sensitive to *when* in the session a scan runs, independent of the code being measured:

- **Cold FS cache**: the first scan of a repo pays the disk-read cost. Mitigated by a discarded per-repo warmup scan (disable with `--no-warmup`).
- **CPU thermal throttling / frequency scaling**: on laptops especially, later scans in a long session run slower. If each variant's repetitions ran back to back, whichever variant went first would look systematically faster.

To cancel these, the harness **interleaves** variants: it runs one repetition of each variant per round and rotates the order each round, then takes the minimum wall/CPU time and median peak RSS per variant. Use `--runs 3` (default) or higher for stable numbers; treat single-digit-percent deltas as noise, especially locally. Dedicated CI runners are steadier than laptops but not immune.

## Interpreting the comment

- **scanner trigger:** a finding-count delta means the engine changed behaviour, usually something to justify. Time/memory increases beyond the thresholds are flagged ⚠️.
- **rules trigger:** a finding-count delta is expected (it's the whole point); the value is spotting unintended time/memory blowups.

Thresholds (`TIME_REGRESSION_PCT`, `MEM_REGRESSION_PCT`) live in `models.py`.
