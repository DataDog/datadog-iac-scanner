---
title: "EKS cluster logging is not enabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/eks_cluster_log_disabled"
  id: "terraform-aws-eks-cluster-logging-is-not-enabled"
  display_name: "EKS cluster logging is not enabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `terraform-aws-eks-cluster-logging-is-not-enabled`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types)

### Description

Amazon EKS control plane logging should be enabled to capture important events and API calls within the Kubernetes control plane. Without explicit configuration of the `enabled_cluster_log_types` attribute, as shown below, critical logs like API, audit, and authenticator events will not be sent to CloudWatch, making it difficult to monitor cluster activity or investigate potential security incidents.

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
  name                      = var.cluster_name
}

```