---
title: "Dependabot execution"
group_id: "CICD / GitHub"
meta:
  name: ""github/dependabot_execution""
  id: "cicd-github-dependabot-execution"
  display_name: "Dependabot execution"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "HIGH"
  category: "Supply-Chain"
---
## Metadata

**Id:** {{< copyable-code >}}cicd-github-dependabot-execution{{< /copyable-code >}}

**Provider:** GitHub

**Platform:** CICD

**Severity:** High

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#insecure-external-code-execution)

### Description

Dependabot updates must not be configured to execute untrusted external code. Allowing install scripts or arbitrary code from dependencies can lead to supply-chain compromise and remote code execution during automated updates. The `insecure-external-code-execution` property under each `updates` entry in the Dependabot configuration (dependabot.yml) must be set to the string `deny` or omitted, as the default is `deny`. Entries with `insecure-external-code-execution: allow` will be flagged.

Secure configuration example:

```yaml
version: 2

updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: daily
    insecure-external-code-execution: deny
```

## Compliant Code Examples
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    insecure-external-code-execution: deny

  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    # Default is deny when omitted

```
## Non-Compliant Code Examples
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    insecure-external-code-execution: allow

```