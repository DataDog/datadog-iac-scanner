---
title: "Output without description"
group_id: "Terraform / Common"
meta:
  name: "general/output_without_description"
  id: "59312e8a-a64e-41e7-a252-618533dd1ea8"
  display_name: "Output without description"
  cloud_provider: "Common"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `59312e8a-a64e-41e7-a252-618533dd1ea8`

**Cloud Provider:** Common

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/language/values/outputs.html#description-output-value-documentation)

### Description

 `output` entries must contain a valid `description`.
The `description` must be defined, non-null, and not empty or whitespace-only.


## Compliant Code Examples
```terraform
output "cluster_name" {
  value = "example"
  description = "cluster name"
}

resource "aws_eks_cluster" "negative1" {
  depends_on = [aws_cloudwatch_log_group.example]

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

```
## Non-Compliant Code Examples
```terraform
output "cluster_name" {
  value = "example"
  description = " "
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
}

```

```terraform
output "cluster_name" {
  value = "example"
  description = ""
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
}

```

```terraform
output "cluster_name" {
  value = "example"
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]
}

```