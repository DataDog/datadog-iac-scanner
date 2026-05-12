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

* For Linux, choose the latest `datadog-iac-scanner_X.Y.Z_linux_amd64.tar.gz` (x86_64) or `datadog-iac-scanner_X.Y.Z_linux_arm64.tar.gz` (ARM64) file.
* For macOS, choose the latest `datadog-iac-scanner_X.Y.Z_darwin_arm64.tar.gz` file. Intel hardware is not supported.
* For Windows, choose the latest `datadog-iac-scanner_X.Y.Z_windows_amd64.zip` file.

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

Run `datadog-iac-scanner scan --help` to see all available flags.

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
