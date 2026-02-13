---
title: "Shield Advanced not in use"
group_id: "Terraform / AWS"
meta:
  name: "aws/shield_advanced_not_in_use"
  id: "084c6686-2a70-4710-91b1-000393e54c12"
  display_name: "Shield Advanced not in use"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `084c6686-2a70-4710-91b1-000393e54c12`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/shield_protection#resource_arn)

### Description

 AWS Shield Advanced provides enhanced protection against distributed denial-of-service (DDoS) attacks for critical AWS resources, such as Amazon Route 53 hosted zones, AWS Global Accelerator accelerators, Elastic IP addresses, Elastic Load Balancers, and Amazon CloudFront distributions. Without Shield Advanced enabled, these resources are vulnerable to large-scale DDoS attacks, which can lead to downtime, degraded performance, and increased mitigation costs. To secure these resources in Terraform, use the `aws_shield_protection` resource with the correct `resource_arn`. For example:

```
resource "aws_shield_protection" "example" {
  name         = "example"
  resource_arn = "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:eip-allocation/${aws_eip.example.id}"

  tags = {
    Environment = "Prod"
  }
}
```


## Compliant Code Examples
```terraform
resource "aws_route53_zone" "negative2" {
  name = "example.com"
}

resource "aws_shield_protection" "negative2" {
  name         = "example"
  resource_arn = aws_route53_zone.negative2.arn

  tags = {
    Environment = "Dev"
  }
}

```

```terraform
data "aws_availability_zones" "available" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_eip" "negative1" {
  vpc = true
}

resource "aws_shield_protection" "negative1" {
  name         = "example"
  resource_arn = "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:eip-allocation/${aws_eip.negative1.id}"

  tags = {
    Environment = "Dev"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_route53_zone" "positive2" {
  name = "example.com"
}

resource "aws_shield_protection" "positive2" {
  name         = "example"
  resource_arn = aws_route53_zone.positive.arn

  tags = {
    Environment = "Dev"
  }
}

```

```terraform
data "aws_availability_zones" "available" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_eip" "positive1" {
  vpc = true
}

resource "aws_shield_protection" "positive1" {
  name         = "example"
  resource_arn = "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:eip-allocation/${aws_eip.positive.id}"

  tags = {
    Environment = "Dev"
  }
}

```