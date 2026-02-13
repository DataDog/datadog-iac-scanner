---
title: "Variable without description"
group_id: "Terraform / Common"
meta:
  name: "general/variable_without_description"
  id: "2a153952-2544-4687-bcc9-cc8fea814a9b"
  display_name: "Variable without description"
  cloud_provider: "Common"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `2a153952-2544-4687-bcc9-cc8fea814a9b`

**Cloud Provider:** Common

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/language/values/variables.html#input-variable-documentation)

### Description

 All variables must include a `description` attribute that is defined, not null, and not empty or whitespace-only.

This rule reports:

- `MissingAttribute` when the `description` key is undefined or null.
- `IncorrectValue` when the `description` is present but empty after trimming.

Each result includes `documentId`, `resourceType`, `resourceName`, and `searchKey` to help locate the offending variable.


## Compliant Code Examples
```terraform
variable "cluster_name" {
  default = "example"
  description = "cluster name"
  type    = string
}

resource "aws_eks_cluster" "negative1" {
  depends_on = [aws_cloudwatch_log_group.example]

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  name                      = var.cluster_name
}

```
## Non-Compliant Code Examples
```terraform
variable "cluster_name" {
  default = "example"
  type    = string
  description = " "
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
  name                      = var.cluster_name
}

```

```terraform
variable "cluster_name" {
  default = "example"
  type    = string
  description = ""
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
  name                      = var.cluster_name
}

```

```terraform
variable "cluster_name" {
  default = "example"
  type    = string
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
  name                      = var.cluster_name
}

```