---
title: "Indefinitely Databricks OBO token lifetime"
group_id: "Terraform / Databricks"
meta:
  name: "databricks/indefinitely_obo_token"
  id: "terraform-common-indefinitely-obo-token"
  display_name: "Indefinitely Databricks OBO token lifetime"
  cloud_provider: "Databricks"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `terraform-common-indefinitely-obo-token`

**Cloud Provider:** Databricks

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/databricks/databricks/latest/docs/resources/obo_token)

### Description

`databricks_obo_token` has an indefinite lifetime.
OBO tokens must include a `lifetime_seconds` attribute to enforce a finite validity period.
This rule flags any `databricks_obo_token` resource that does not set `lifetime_seconds`.

## Compliant Code Examples
```terraform
resource "databricks_obo_token" "negative" {
  depends_on       = [databricks_group_member.this]
  application_id   = databricks_service_principal.this.application_id
  comment          = "PAT on behalf of ${databricks_service_principal.this.display_name}"
  lifetime_seconds = 3600
}

```
## Non-Compliant Code Examples
```terraform
resource "databricks_obo_token" "positive" {
  depends_on       = [databricks_group_member.this]
  application_id   = databricks_service_principal.this.application_id
  comment          = "PAT on behalf of ${databricks_service_principal.this.display_name}"
}

```