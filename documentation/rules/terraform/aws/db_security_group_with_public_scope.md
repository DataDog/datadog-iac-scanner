---
title: "DB security group with public scope"
group_id: "Terraform / AWS"
meta:
  name: "aws/db_security_group_with_public_scope"
  id: "1e0ef61b-ad85-4518-a3d3-85eaad164885"
  display_name: "DB security group with public scope"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `1e0ef61b-ad85-4518-a3d3-85eaad164885`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/rgeraskin/aws3/latest/docs/resources/db_security_group)

### Description

AWS DB security groups with overly permissive ingress rules (`0.0.0.0/0` or `::/0`) expose database instances to potential unauthorized access from any IP address on the internet. This critical security vulnerability could lead to data breaches, unauthorized data manipulation, or complete database compromise. Instead of using public CIDR ranges, restrict access to specific IP ranges that require database connectivity.

Insecure example:
```terraform
resource "aws_db_security_group" "insecure" {
  name = "rds_sg"
  ingress {
    cidr = "0.0.0.0/0"
  }
}
```

Secure example:
```terraform
resource "aws_db_security_group" "secure" {
  name = "rds_sg"
  ingress {
    cidr = "10.0.0.0/25"
  }
}
```

## Compliant Code Examples
```terraform
resource "aws_db_security_group" "negative1" {
  name = "rds_sg"

  ingress {
    cidr = "10.0.0.0/25"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_db_security_group" "positive1" {
  name = "rds_sg"

  ingress {
    cidr = "0.0.0.0/0"
  }
}
```