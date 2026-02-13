---
title: "Resource not using tags"
group_id: "Terraform / AWS"
meta:
  name: "aws/resource_not_using_tags"
  id: "e38a8e0a-b88b-4902-b3fe-b0fcb17d5c10"
  display_name: "Resource not using tags"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `e38a8e0a-b88b-4902-b3fe-b0fcb17d5c10`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging)

### Description

 AWS resource tagging is an essential best practice that supports resource management, cost tracking, automation, and security enforcement. If only the default `Name` tag is applied and no additional metadata tags (such as `Environment`, `Owner`, or `Project`) are defined, resources may become difficult to identify, audit, and manage at scale, increasing the risk of misconfiguration or unintended resource exposure. For example, a secure configuration should use a `tags` block with descriptive tags:

```
tags = {
  Name        = "example-cert"
  Environment = "production"
  Owner       = "devops-team"
}
```


## Compliant Code Examples
```terraform
resource "aws_acm_certificate" "cert" {
  domain_name       = "example.com"
  validation_method = "DNS"

  tags = {
    Environment = "test"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "example" {
  certificate_arn         = aws_acm_certificate.example.arn
  validation_record_fqdns = [for record in aws_route53_record.example : record.fqdn]
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_acm_certificate" "cert" {
  domain_name       = "example.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate" "cert_2" {
  domain_name       = "example.com"
  validation_method = "DNS"

  tags = {
    Name = "test"
  }

  lifecycle {
    create_before_destroy = true
  }
}

```