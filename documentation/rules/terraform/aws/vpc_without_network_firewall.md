---
title: "VPC without Network Firewall"
group_id: "Terraform / AWS"
meta:
  name: "aws/vpc_without_network_firewall"
  id: "terraform-aws-vpc-without-network-firewall"
  display_name: "VPC without Network Firewall"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-aws-vpc-without-network-firewall{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/networkfirewall_firewall#vpc_id)

### Description

This check ensures that every Amazon Virtual Private Cloud (VPC) has an AWS Network Firewall associated with it for advanced network traffic filtering and threat protection. Without a Network Firewall, the VPC is left vulnerable to attacks such as unauthorized access, data exfiltration, and propagation of malware between workloads and subnets. Associating a Network Firewall with the VPC allows administrators to define and enforce rules that control both inbound and outbound traffic, enhancing security posture. Failing to implement this safeguard can result in greater exposure to network-based attacks or unmonitored lateral movement within the cloud environment.

## Compliant Code Examples
```terraform
resource "aws_vpc" "negative" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_networkfirewall_firewall" "example" {
  name                = "example"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.example.arn
  vpc_id              = aws_vpc.negative.id
  subnet_mapping {
    subnet_id = aws_subnet.example.id
  }

  tags = {
    Tag1 = "Value1"
    Tag2 = "Value2"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_vpc" "positive" {
  cidr_block = "10.0.0.0/16"
}

```