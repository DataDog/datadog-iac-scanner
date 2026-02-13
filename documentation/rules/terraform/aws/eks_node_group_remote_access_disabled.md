---
title: "EKS node group remote access disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/eks_node_group_remote_access_disabled"
  id: "ba40ace1-a047-483c-8a8d-bc2d3a67a82d"
  display_name: "EKS node group remote access disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ba40ace1-a047-483c-8a8d-bc2d3a67a82d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_node_group#remote_access)

### Description

This check ensures that when configuring remote access for an AWS EKS node group, the `source_security_group_ids` attribute is specified. If this parameter is omitted, the EC2 instances in the EKS node group can potentially be accessed via SSH from any IP address, which significantly increases the risk of unauthorized access. By not restricting SSH access to a specific set of trusted security groups, the node group becomes more vulnerable to brute force attacks and other security threats. Properly configuring the `source_security_group_ids` limits remote access to only those network sources that are explicitly permitted, thereby reducing the node group’s attack surface.

## Compliant Code Examples
```terraform
resource "aws_eks_node_group" "negative" {
  cluster_name    = aws_eks_cluster.example.name
  node_group_name = "example"
  node_role_arn   = aws_iam_role.example.arn
  subnet_ids      = aws_subnet.example[*].id

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  remote_access {
    ec2_ssh_key = "my-rsa-key"
    source_security_groups_ids = "sg-213120ASNE"
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.example-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.example-AmazonEC2ContainerRegistryReadOnly,
  ]
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_eks_node_group" "positive" {
  cluster_name    = aws_eks_cluster.example.name
  node_group_name = "example"
  node_role_arn   = aws_iam_role.example.arn
  subnet_ids      = aws_subnet.example[*].id

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  remote_access {
    ec2_ssh_key = "my-rsa-key"
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.example-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.example-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.example-AmazonEC2ContainerRegistryReadOnly,
  ]
}

```