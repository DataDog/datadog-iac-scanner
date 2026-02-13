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

Create a file named `dd-iac-scan.config` in your repository to customize scanner behavior. Use this file to exclude specific categories, paths, severities, or queries. The file can be written in YAML, JSON, TOML, or HCL.

```yaml
exclude-severities:
  - "info"
  - "low"
exclude-paths:
  - "./shouldNotScan/*"
  - "dir/somefile.txt"
exclude-queries:
  - "e69890e6-fce5-461d-98ad-cb98318dfc96"
  - "4728cd65-a20c-49da-8b31-9c08b423e4db"
exclude-categories:
  - "Access Control"
  - "Best Practices"
```

You can also use inline comments to exclude files, blocks, and individual lines from scan results. Add a comment starting with `# dd-iac-scan` followed by a command.

| Comment | Description |
|---------|-------------|
| `# dd-iac-scan ignore-line` | Ignores findings on the next line. |
| `# dd-iac-scan ignore-block` | Ignores findings in the following block. |
| `# dd-iac-scan ignore` | Ignores findings in the entire file. Must appear at the beginning of the file. |
| `# dd-iac-scan disable=queryId` | Ignores results for the specified query ID. Must appear at the beginning of the file; applies to the whole file. |
| `# dd-iac-scan enable=queryId` | Ignores results for all queries _except_ the specified query ID. Must appear at the beginning of the file; applies to the whole file. |

See the [exclusions documentation](https://docs.datadoghq.com/security/code_security/iac_security/exclusions/) for more information.

## License

Datadog IaC Scanner is licensed under the [Apache License, Version 2.0](LICENSE).

## Acknowledgment

This project is based on [KICS](https://github.com/Checkmarx/kics), developed by Checkmarx and released under the Apache License 2.0. It extends the original project with Datadog platform integration and additional rule coverage. For more details, see the [Datadog IaC Security documentation](https://docs.datadoghq.com/security/code_security/iac_security/).
