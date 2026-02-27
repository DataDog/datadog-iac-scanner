---
title: "EMR without VPC"
group_id: "Terraform / AWS"
meta:
  name: "aws/emr_without_vpc"
  id: "2b3c8a6d-9856-43e6-ab1d-d651094f03b4"
  display_name: "EMR without VPC"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `2b3c8a6d-9856-43e6-ab1d-d651094f03b4`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster#subnet_id)

### Description

This check ensures that Amazon Elastic MapReduce (EMR) clusters are deployed within a Virtual Private Cloud (VPC) by specifying a `subnet_id` in the Terraform resource. Launching EMR clusters without associating them to a VPC, as shown by omitting the `subnet_id` attribute in the `aws_emr_cluster` resource, exposes the cluster to public networks and increases the risk of unauthorized access or data compromise. By deploying EMR clusters in a VPC, network access control can be properly enforced through security groups and network ACLs, limiting exposure to only trusted sources. Failure to launch EMR clusters inside a VPC can lead to serious security vulnerabilities, including unauthorized data access, data exfiltration, or service disruption.

## Compliant Code Examples
```terraform
resource "aws_emr_cluster" "negative1" {
  name          = "emr-test-arn"
  release_label = "emr-4.6.0"
  subnet_id = aws_subnet.main.id
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_emr_cluster" "positive1" {
  name          = "emr-test-arn"
  release_label = "emr-4.6.0"
}

```