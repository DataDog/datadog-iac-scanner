# Legacy Configuration File

Datadog IaC Scanner has backwards-compatible support for the legacy `dd-iac-scan.config`
configuration file, which has a different schema and semantics than the current
`code-security.datadog.yaml` configuration schema (see the
[IaC Security configuration documentation](https://docs.datadoghq.com/security/code_security/iac_security/configuration/)).

Users may continue to use a `dd-iac-scan.config` file with no disruptions or behavior
changes. The legacy schema is deprecated and does not receive new updates: prefer
configuring the scanner with `code-security.datadog.yaml` and `schema-version` `v1.2` or
higher for new repositories.

When both files are present, a `code-security.datadog.yaml` file with an `iac` section
takes precedence over `dd-iac-scan.config`. If the `code-security.datadog.yaml` file has
no `iac` section (for example, only `sast`), the scanner falls back to
`dd-iac-scan.config`.

Documentation for the legacy format has been saved below for reference:

---

## Legacy Schema Reference

The scanner can be configured using a `dd-iac-scan.config` file at the root directory of
the repository. The file can be written in YAML, JSON, TOML, or HCL; the format is
detected from the file extension.

The following top-level entries are supported:

- `exclude-severities`: (optional) a list of severities to ignore. Findings whose
  severity matches an entry in this list are dropped from scan results.
- `exclude-paths`: (optional) a list of paths or glob patterns to exclude from scanning.
  Files matching any entry are not analyzed.
- `exclude-queries`: (optional) a list of query (rule) IDs to ignore. Findings produced
  by these queries are dropped from scan results. Both legacy UUID rule IDs and the new
  Code Security rule IDs are accepted.
- `exclude-categories`: (optional) a list of categories to ignore. Findings whose
  category matches an entry in this list are dropped from scan results.
- `include-queries`: (optional) a list of query (rule) IDs to run. If `include-queries`
  is set, every `exclude-*` field in the same file is ignored and only the listed
  queries are evaluated.

### Possible values

`exclude-severities` accepts the following values:

- `critical`
- `high`
- `medium`
- `low`
- `info`

`exclude-categories` accepts the following values:

- `Access Control`
- `Availability`
- `Backup`
- `Best Practices`
- `Bill Of Materials`
- `Build Process`
- `Encryption`
- `Insecure Configurations`
- `Insecure Defaults`
- `Networking and Firewall`
- `Observability`
- `Resource Management`
- `Secret Management`
- `Structure and Semantics`
- `Supply-Chain`

## Examples

### YAML

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

### JSON

```json
{
  "exclude-severities": ["info", "low"],
  "exclude-paths": ["./shouldNotScan/*", "dir/somefile.txt"],
  "exclude-queries": [
    "e69890e6-fce5-461d-98ad-cb98318dfc96",
    "4728cd65-a20c-49da-8b31-9c08b423e4db"
  ],
  "exclude-categories": ["Access Control", "Best Practices"]
}
```

### TOML

```toml
exclude-severities = ["info", "low"]
exclude-paths = ["./shouldNotScan/*", "dir/somefile.txt"]
exclude-queries = [
  "e69890e6-fce5-461d-98ad-cb98318dfc96",
  "4728cd65-a20c-49da-8b31-9c08b423e4db",
]
exclude-categories = ["Access Control", "Best Practices"]
```

### HCL

```hcl
"exclude-severities" = ["info", "low"]
"exclude-paths" = ["./shouldNotScan/*", "dir/somefile.txt"]
"exclude-queries" = [
  "e69890e6-fce5-461d-98ad-cb98318dfc96",
  "4728cd65-a20c-49da-8b31-9c08b423e4db",
]
"exclude-categories" = ["Access Control", "Best Practices"]
```

## Run only specific queries

Use `include-queries` to run only specific queries in a repository:

```yaml
include-queries:
  - "e69890e6-fce5-461d-98ad-cb98318dfc96"
  - "4728cd65-a20c-49da-8b31-9c08b423e4db"
```

When `include-queries` is set, the scanner evaluates only the listed queries and ignores
every `exclude-*` field in the same `dd-iac-scan.config` file.

## Inline comments

Inline comments (`dd-iac-scan ignore`, `dd-iac-scan disable=<rule_id>`,
`dd-iac-scan enable=<rule_id>`, `dd-iac-scan ignore-line`, `dd-iac-scan ignore-block`)
are part of the scanner itself rather than the legacy configuration file, so they
continue to work the same way with both `code-security.datadog.yaml` and
`dd-iac-scan.config`. See the
[IaC Security configuration documentation](https://docs.datadoghq.com/security/code_security/iac_security/configuration/)
for the full list of supported inline commands.
