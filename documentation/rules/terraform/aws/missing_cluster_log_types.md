---
title: "Missing cluster log types"
group_id: "Terraform / AWS"
meta:
  name: "aws/missing_cluster_log_types"
  id: "66f130d9-b81d-4e8e-9b08-da74b9c891df"
  display_name: "Missing cluster log types"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `66f130d9-b81d-4e8e-9b08-da74b9c891df`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/providers/aws/r/eks_cluster.html)

### Description

 Amazon EKS clusters provide several control plane log types, such as `api`, `audit`, `authenticator`, `controllerManager`, and `scheduler`, which should all be enabled for comprehensive monitoring and security auditing. If some log types are omitted in Terraform, as in the example below, critical events may go unlogged, impeding detection and investigation of suspicious activity or configuration issues within the EKS control plane:

```
enabled_cluster_log_types = ["api", "audit"]
```

Enabling all log types mitigates blind spots and enhances security visibility, as demonstrated in the following example:

```
enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
```


## Compliant Code Examples
```terraform
variable "cluster_name" {
  default = "example"
  type    = string
}

resource "aws_eks_cluster" "negative1" {
  depends_on = [aws_cloudwatch_log_group.example]

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  name                      = var.cluster_name

  # ... other configuration ...
}

resource "aws_cloudwatch_log_group" "negative2" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 7

  # ... potentially other configuration ...
}

```
## Non-Compliant Code Examples
```terraform
variable "cluster_name" {
  default = "example"
  type    = string
}

resource "aws_eks_cluster" "positive1" {
  depends_on = [aws_cloudwatch_log_group.example]

  enabled_cluster_log_types = ["api", "audit"]
  name                      = var.cluster_name

  # ... other configuration ...
}

resource "aws_cloudwatch_log_group" "positive2" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 7

  # ... potentially other configuration ...
}

```