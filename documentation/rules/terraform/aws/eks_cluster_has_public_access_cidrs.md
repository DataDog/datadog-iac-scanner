---
title: "EKS cluster has public access CIDRs"
group_id: "Terraform / AWS"
meta:
  name: "aws/eks_cluster_has_public_access_cidrs"
  id: "61cf9883-1752-4768-b18c-0d57f2737709"
  display_name: "EKS cluster has public access CIDRs"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `61cf9883-1752-4768-b18c-0d57f2737709`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster)

### Description

Enabling the Amazon EKS public endpoint and allowing access from all IP addresses (`0.0.0.0/0`) exposes the Kubernetes cluster's API server to the entire internet. This configuration creates a significant security risk, as it allows unauthorized parties to attempt authentication or exploit vulnerabilities in the API server from anywhere in the world. If left unaddressed, this could lead to unauthorized access, data breaches, or disruption of workloads orchestrated by the cluster. Limiting public access to trusted IP address ranges greatly reduces the attack surface and helps safeguard sensitive operations and cluster resources.

## Compliant Code Examples
```terraform
resource "aws_eks_cluster" "negative1" {
  name     = "example"
  role_arn = aws_iam_role.example.arn

  vpc_config {
    subnet_ids = [aws_subnet.example1.id, aws_subnet.example2.id]
    endpoint_public_access = true
    public_access_cidrs = ["1.1.1.1/1"]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSClusterPolicy,
  ]
}

output "endpoint" {
  value = aws_eks_cluster.example.endpoint
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.example.certificate_authority[0].data
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_eks_cluster" "positive1" {
  name     = "example"
  role_arn = aws_iam_role.example.arn

  vpc_config {
    subnet_ids = [aws_subnet.example1.id, aws_subnet.example2.id]
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSClusterPolicy,
  ]
}

output "endpoint" {
  value = aws_eks_cluster.example.endpoint
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.example.certificate_authority[0].data
}

resource "aws_eks_cluster" "positive2" {
  name     = "without_example"
  role_arn = aws_iam_role.example.arn

  vpc_config {
    subnet_ids = [aws_subnet.example1.id, aws_subnet.example2.id]
    endpoint_public_access = true
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSClusterPolicy,
  ]
}
```