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

### Additive Terraform evaluator facts

Terraform rules that need evaluator state can read the optional sidecar at
`input._dd.documents[document_id]`. The key is the same `id` used by the
corresponding entry in `input.document`; the sidecar does not change that
document. Each document fact reports coverage for represented Terraform
resource and data subjects only; `complete` does not prove that no other
subject exists outside those entries. A subject's `source_document_id` points
to the original HCL document, which can differ from the evaluated `document_id`
for a module document. Paths are arrays of strings (object keys) and integers
(collection indices). A sidecar entry has this shape:

```json
{
  "platform": "terraform",
  "coverage": "complete",
  "subjects": [{
    "source_document_id": "tf-root-id",
    "path": ["resource", "aws_s3_bucket", "bucket"],
    "address": "aws_s3_bucket.bucket",
    "address_complete": true,
    "instance_set": "complete",
    "values": [{
      "path": ["tags", "team"],
      "native_state": "known",
      "presentation": "native",
      "children": "unknown"
    }]
  }]
}
```

A rule can inspect facts independently of the legacy document, for example:

```rego
has_unknown_value if {
  some document_id
  facts := input._dd.documents[document_id]
  some subject in facts.subjects
  some value in subject.values
  value.native_state == "unknown"
}
```

| Field | Values | Meaning |
|---|---|---|
| `coverage`, `instance_set` | `complete`, `incomplete`, `unproven` | Completeness of facts for represented subjects in this OPA document, or completeness of that subject's instance set. `complete` does not establish that no other resource or data block exists outside the document. |
| `platform` | `terraform` | The platform whose evaluator facts are represented by this entry. |
| `reasons` | optional strings | Why coverage was reduced. Current reasons include `facts_truncated`, `shared_evaluation_context`, `document_subject_shape_unknown`, `no_subjects_emitted`, `fact_subject_mapping_unproven`, `document_subject_without_fact`, and `fact_subject_not_in_document`. |
| `source_document_id`, `path` | string; mixed string/integer array | Original source document ID and the subject/value location in the legacy document shape. |
| `address` | optional string | Evaluated Terraform subject address. Its completeness is reported separately. |
| `address_complete` | `true`, `false` | Whether the subject address is fully known. This is independent of `instance_set`. |
| `values` | array of value facts | Native state, presentation, child state, and typed path for extracted values; the array may be partial when truncated. |
| `native_state` | `known`, `null`, `unknown`, `partial` | Evaluator state before legacy document presentation. |
| `presentation` | `native`, `adapted`, `managed_reference`, `source_expression`, `unknown_placeholder`, `unproven` | How the existing document presents that value. Read this with `native_state`; `adapted` means legacy projection changed structure/content or the value contains non-native descendants. `children` independently reports nested membership. `unproven` means presentation fidelity could not be established, for example after extraction truncation. |
| `children` | `closed`, `open`, `unknown` | Whether nested child paths are known from the evaluated/configuration shape. `closed` does not include provider defaults. |
| `values_truncated` | `true` when present | Fact extraction hit its depth or node budget; the subject's `values` list may be partial. |

Fact extraction is bounded to 64 levels and 8192 value records per subject.
Truncated document coverage includes the `facts_truncated` reason. Missing facts,
including absent document or value entries, mean unknown rather than proof that
the configuration has no such resource or value.

Fallback, plan-derived, external, or otherwise partial scopes may have no native
facts or may be marked `unproven`/`incomplete`. A synthetic module document
shared across caller contexts omits context-specific subjects and is marked
`unproven`. These states must remain unknown to a consuming rule.

The sidecar copies no attribute values or source expressions, though object
keys and evaluated instance keys/addresses can appear in paths. The facts do not identify
whether a value came from a variable default or whether it was marked
sensitive; do not infer either from these fields. The legacy document and
finding interface is retained. Fact extraction is enabled when a selected
Terraform or common rule or loaded library may read input outside
`input.document`; imported input aliases and whole-input references are treated
conservatively. Facts-aware scans evaluate resource and data subjects
conservatively rather than using type or subset shortcuts. When all selected
Terraform/common rules and loaded libraries only read `input.document`, no
native fact projections are allocated.

### CI/CD source parsing

Canonical GitHub workflow files under `.github/workflows/` and GitLab entrypoints
are routed to CI/CD, honoring platform exclusions. Action manifests are detected
by their content: naming a Kubernetes, Ansible or Helm file `action.yml` or
`action.yaml` does not change its platform. Content-based workflow discovery also
accepts quoted keys and whitespace before colons. CI scalar values remain literal;
naming a sibling YAML file does not inline its contents.

GitHub job and step conditions support implicit expressions, multiline values
and quoted delimiters. Shell settings follow step, job and workflow defaults,
then container or recognized runner labels. PowerShell remains unsupported by the
shell parser, whether selected explicitly or by a Windows runner; existing rules
may use their text fallbacks. Unresolved runners retain a Bash analysis candidate,
which does not establish their actual OS or shell. Composite run steps require an
explicit shell. Expressions are never executed. Pipelines writing GitHub
environment/path files are analyzed conservatively and may be reported even
when their arguments appear literal.


### GitLab CI declaration inventory

The CI/CD platform discovers canonical `.gitlab-ci.yml` and
`.gitlab-ci.yaml` files and inventories their directly declared, non-hidden
mapping entries as `gitlab_ci_job` resources with source ranges. Reserved
pipeline sections and hidden templates are excluded. Inventory describes
declarations in each file, not the jobs GitLab will execute or their validity.
Canonical filenames are discovered in nested directories too, including templates
and fixtures. If YAML parsing fails for a discovered file, inventory records a
failed file and a partial status even when the root entrypoint parses successfully.
Exclude fixture/template paths with the existing scan path exclusions when they
should not be analyzed.

This support uses the existing YAML parser. It does not compile includes,
`extends`, `!reference`, inputs or defaults, evaluate job conditions, add shell
analysis, or introduce GitLab security rules. Custom entrypoints and fragments
are not discovered as GitLab CI. GitHub workflow paths retain their existing
behavior.

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
