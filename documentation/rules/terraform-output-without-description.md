---
title: "Output without description"
group_id: "Terraform / Terraform"
meta:
  name: "terraform/output_without_description"
  id: "terraform-output-without-description"
  display_name: "Output without description"
  cloud_provider: "Terraform"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-output-without-description{{< /copyable-code >}}

**Provider:** Terraform

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