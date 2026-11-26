# Datadog IaC Scanner

This repository contains the source code of the Datadog IaC Scanner.

The scanner finds security vulnerabilities, compliance issues, and infrastructure misconfigurations early in the development cycle of your infrastructure-as-code. It produces standard [SARIF](https://sarifweb.azurewebsites.net/) output that can be integrated with Datadog or any other tool that consumes SARIF.

This project was forked from [Checkmarx KICS](https://github.com/Checkmarx/kics).

## Getting started

1. [Download](#installation) or [build](#building-from-source) the binary.
2. Add a [configuration](#configuring-the-scan) file to your repository (optional).
3. [Run](#usage) the scanner.

### Installation

Visit the [releases](https://github.com/DataDog/datadog-iac-scanner/releases) page and download the binary archive for your operating system and architecture.

* For Linux, choose the latest `datadog-iac-scanner_linux_amd64.tar.gz` (x86_64) or `datadog-iac-scanner_linux_arm64.tar.gz` (ARM64) file.
* For macOS, choose the latest `datadog-iac-scanner_darwin_amd64.tar.gz` (Intel) or `datadog-iac-scanner_darwin_arm64.tar.gz` (Apple Silicon) file.
* For Windows, choose the latest `datadog-iac-scanner_windows_amd64.zip` file.

### Building from source

Clone the repository or download a source code archive from the [releases](https://github.com/DataDog/datadog-iac-scanner/releases) page, then run:

```bash
make build
```

The binary will be available at `bin/datadog-iac-scanner`.

### Usage

Scan the directory `REPODIR` and write SARIF output to `OUTPUTDIR`:

```bash
datadog-iac-scanner scan -p REPODIR -o OUTPUTDIR
```

`REPODIR` must be within a Git repository. You can also specify file names, or multiple directories and files, as long as they all reside in the same Git repository:

```
datadog-iac-scanner scan -p REPODIR/file1.yaml -p REPODIR/otherdir/file2.yaml -p REPODIR/anotherdir -o OUTPUTDIR
```

You can also use commas instead of repeating the `-p` flag:

```bash
datadog-iac-scanner scan -p REPODIR/file1.yaml,REPODIR/otherdir/file2.yaml,REPODIR/anotherdir -o OUTPUTDIR
```

By default, the output file is named `datadog-iac-scanner-result.sarif`. Use `--output-name` to specify a different name:

```bash
datadog-iac-scanner scan -p REPODIR -o OUTPUTDIR --output-name OUTPUTFILE.sarif
```

You can run the scanner using your own local rules, written in the QUERYDIR directory, with the -q flag:

```bash
datadog-iac-scanner scan -p REPODIR -o OUTPUTDIR -q QUERYDIR
```

The rule directories in the QUERYDIR directory must contain a 'query.rego' and a 'metadata.json' file. You can also specify multiple paths:

```bash
datadog-iac-scanner scan -p REPODIR -o OUTPUTDIR -q QUERYDIR1 -q QUERYDIR2
```

Run `datadog-iac-scanner scan --help` to see all available flags.

### GitLab CI parsing

The CI/CD platform recognizes `.gitlab-ci.yml`, `.gitlab-ci.yaml`, files ending in
`.gitlab-ci.yml` or `.gitlab-ci.yaml`, and GitLab CI templates under `.gitlab/ci/`.
Standalone templates can contain only hidden definitions or pipeline globals.
It resolves local includes within the repository (including wildcard patterns),
YAML anchors, `extends`, `!reference`, and simple input defaults and overrides.
Scalar values follow GitLab's Psych boolean resolution: plain `yes`/`on` and
`no`/`off` become booleans, while quoted strings retain their type, including
through includes and whole-value input substitutions. Status-mirroring
`needs:pipeline` jobs are included even without an explicit stage or script.
After inheritance, jobs receive missing `default` keywords (or deprecated global
defaults), respecting `inherit:default` and preserving explicit job values.
Inherited defaults retain their declaring sources and shared command analysis.
Included executable jobs retain their source file paths and obey scan path filters.
Findings use the contributing field’s source and suppression directives, including
merged jobs and pipeline globals. Rules see one compiled pipeline per
YAML document under `input.document[i].gitlab`; scanner `id` and `file` metadata
remain on the outer document, so jobs with those names are preserved. Typed
finding paths begin with `"gitlab"`, such as `["gitlab", "build", "script", 0]`.
Source positions are stored outside the configuration. Parsed pipeline-wide
`before_script` and `after_script` analysis is available under the outer
`input.document[i].gitlab_scripts` object, keyed by the original field name;
job-local analysis remains in each job's `_parsed_*` fields. This preserves jobs
named `_dd_lines`, `_parsed_before_script`, or `_parsed_after_script`.
Source files remain location metadata. Included files are registered once per pipeline
compilation, while files scanned without their parent retain standalone coverage. An include whose first
rule unconditionally says `when: never` is skipped. Locally decidable
`rules:exists` conditions support files, directory paths and globs, including
the `paths` form and ordered `when` decisions. Globs follow Ruby's pathname,
dotmatch and brace-alternative semantics; terminal `**` does not recurse.
Brace alternatives share a graph rather than expanding every combination.
Patterned existence predicates follow GitLab's own comparison-budget match
behavior, including per-rule pattern counts and its suffix/top-level shortcuts.
Partial snapshots retain uncertainty when the repository total is unknown.
File symlinks count as repository
entries without following their contents or traversing symlinked directories.
An undecidable conditional include is not merged: unconditional configuration
remains available for rules, while scan metadata and IDE responses report
`incomplete` with an `unresolved_include` diagnostic. Partial IDE snapshots request
missing existence predicates. External projects/refs, remote includes and input
functions are not evaluated. This adds parsing and `gitlab_ci_job` inventory;
GitLab-specific security findings require rules that consume that structure.

Parsing preserves repeated commands and shares reusable templates and shell
analysis, including inline scripts in `run` steps. A file-wide work and allocation allowance protects against excessive
expansion, alongside per-field materialization limits. If a limit is reached,
the file produces no partial documents: its inventory status is `failed` with
reason `resource_limit`, and scan metadata and IDE responses report `incomplete`.
Malformed or non-mapping entrypoints fail atomically with reason `invalid_pipeline`;
invalid or unreadable required includes use `invalid_include`. Disk includes must
be regular files. Both failures produce an incomplete result, which must not
be interpreted as a clean security assessment.
Local include reads also honor the configured scan file-size limit.
Source graphs, buffers and lazy loaders are released after finding decoding when
line-info export is disabled; report snippets retain independent text copies.
Whole-file ignore directives apply to the contributing source independently
for root and included files. IDE snapshots continue requesting missing includes.
IDE requests with absolute file paths should supply `repo_root`, using the same
path convention as `files`, so includes in nested pipelines resolve from the
repository boundary without requiring a pushed `.git` marker.
For wildcard includes, a pushed match does not prove that the directory is complete.
IDE requests may declare fully supplied directory trees in the optional
`complete_directories` array (using the same path convention as `files`). Until
then the response requests the directory in `missing_files` and reports
`incomplete`. Missing required includes inside a declared complete tree are errors.

### Configuring the scan

Create a file named `code-security.datadog.yaml` at the root of your repository to customize scanner behavior. Use this file to choose which rules run, restrict scanning to specific paths, or filter findings by severity and category.

```yaml
schema-version: v1.2
iac:
  # Do not run these rules.
  ignore-rules:
    - A
    - B
  # Run only these rules. If set, all other rules are ignored.
  use-rules:
    - A
  global-config:
    # Only analyze the following paths/files.
    only-paths:
      - "infra/"
    # Do not analyze the following paths/files.
    ignore-paths:
      - "**/*.tfvars"
    # Do not report findings with these severities.
    ignore-severities:
      - info
      - low
    # Do not report findings in these categories.
    ignore-categories:
      - "Best Practices"
```

Replace placeholders such as `A` and `B` with Code Security rule IDs. For the full schema, see the [IaC Security configuration documentation](https://docs.datadoghq.com/security/code_security/iac_security/configuration/).

> The legacy `dd-iac-scan.config` file is still supported for backwards compatibility, but its schema is deprecated and does not receive new updates. See [`legacy_config.md`](legacy_config.md) for its reference.

You can also use inline comments to exclude files, blocks, and individual lines from scan results. Add a comment containing `dd-iac-scan` followed by a command (prefixed with the comment syntax for the file format).

| Comment | Description |
|---------|-------------|
| `# dd-iac-scan ignore-line` | Ignores findings on the next line. |
| `# dd-iac-scan ignore-block` | Ignores findings in the following block. |
| `# dd-iac-scan ignore` | Ignores findings in the entire file. Must appear at the beginning of the file. |
| `# dd-iac-scan disable=<rule_id>` | Ignores findings for the specified rule. Must appear at the beginning of the file; applies to the whole file. |
| `# dd-iac-scan enable=<rule_id>` | Ignores findings for all rules _except_ the specified rule. Must appear at the beginning of the file; applies to the whole file. |

## License

Datadog IaC Scanner is licensed under the [Apache License, Version 2.0](LICENSE).

## Acknowledgment

This project is based on [KICS](https://github.com/Checkmarx/kics), developed by Checkmarx and released under the Apache License 2.0. It extends the original project with Datadog platform integration and additional rule coverage. For more details, see the [Datadog IaC Security documentation](https://docs.datadoghq.com/security/code_security/iac_security/).
