---
title: "Variable without type"
group_id: "Terraform / Common"
meta:
  name: "general/variable_without_type"
  id: "fc5109bf-01fd-49fb-8bde-4492b543c34a"
  display_name: "Variable without type"
  cloud_provider: "Common"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `fc5109bf-01fd-49fb-8bde-4492b543c34a`

**Cloud Provider:** Common

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/language/values/variables.html#input-variable-documentation)

### Description

All variables must include a valid `type` attribute.
The `type` must be defined, not null, and not an empty string after trimming whitespace.

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
  type    = " "
  description = "test"
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
  name                      = var.cluster_name
}

```

```terraform
variable "cluster_name" {
  default = "example"
  type    = ""
  description = "test"
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
  name                      = var.cluster_name
}

```

```terraform
variable "cluster_name" {
  default = "example"
  description = "test"
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
  name                      = var.cluster_name
}

```