---
title: "Beta - Databricks token has indefinite lifetime"
group_id: "Terraform / Databricks"
meta:
  name: "databricks/indefinitely_token"
  id: "7d05ca25-91b4-42ee-b6f6-b06611a87ce8"
  display_name: "Beta - Databricks token has indefinite lifetime"
  cloud_provider: "Databricks"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `7d05ca25-91b4-42ee-b6f6-b06611a87ce8`

**Cloud Provider:** Databricks

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/databricks/databricks/latest/docs/resources/token)

### Description

The `databricks_token` resource is missing the `lifetime_seconds` attribute, resulting in a token with an indefinite lifetime.
This attribute defines the token's validity period and should be set to enforce expiration.

## Compliant Code Examples
```terraform
resource "databricks_token" "negative" {
  provider = databricks.created_workspace
  comment  = "Terraform Provisioning"
  // 100 day token
  lifetime_seconds = 8640000
}

```
## Non-Compliant Code Examples
```terraform
resource "databricks_token" "positive" {
  provider = databricks.created_workspace
  comment  = "Terraform Provisioning"
}

```