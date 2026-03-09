---
title: "Dependabot cooldown"
group_id: "CICD / GitHub"
meta:
  name: "github/dependabot_cooldown"
  id: "f2a3b4c5-d6e7-48f9-a0b1-c2d3e4f5a6b7"
  display_name: "Dependabot cooldown"
  cloud_provider: "GitHub"
  platform: "CICD"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `f2a3b4c5-d6e7-48f9-a0b1-c2d3e4f5a6b7`

**Cloud Provider:** GitHub

**Platform:** CICD

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#cooldown)

### Description

Dependabot updates must include an adequate cooldown period to avoid excessive automated pull requests that can overwhelm maintainers and consume CI/CD resources. In GitHub Dependabot configuration files (.github/dependabot.yml), each `updates` entry should define `cooldown.default-days` and set it to at least 7. If the `cooldown` block is missing or `default-days` is absent Dependabot treats it as 0 (no cooldown) and will be flagged; values less than the configured minimum (7 days by default) are also flagged, and fixes can add or increase `default-days` to 7.

Secure configuration example:

```yaml
updates:
  - package-ecosystem: pip
    directory: /
    cooldown:
      default-days: 7
```

## Compliant Code Examples
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    cooldown:
      default-days: 7

```
## Non-Compliant Code Examples
```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    cooldown:
      default-days: 3

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"

```