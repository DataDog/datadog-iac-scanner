---
title: "DB security group has public interface"
group_id: "Terraform / AWS"
meta:
  name: "aws/db_security_group_has_public_interface"
  id: "f0d8781f-99bf-4958-9917-d39283b168a0"
  display_name: "DB security group has public interface"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `f0d8781f-99bf-4958-9917-d39283b168a0`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/rgeraskin/aws3/latest/docs/resources/db_security_group)

### Description

 AWS DB security groups control access to RDS database instances by defining which IP addresses or Amazon EC2 instances can connect to them. Configuring a DB security group with a public interface (`0.0.0.0/0`) allows unrestricted access from any IP address, potentially exposing your database to unauthorized access and attacks from the internet.

This vulnerability significantly increases the risk of data breaches, unauthorized data access, and potential compromise of sensitive information stored in your database. Instead of using public interfaces, you should restrict access to specific IP ranges or VPC CIDR blocks.

Secure example:
```
resource "aws_db_security_group" "example" {
  name = "rds_sg"

  ingress {
    cidr = "10.0.0.0/8"
  }
}
```

Insecure example:
```
resource "aws_db_security_group" "example" {
  name = "rds_sg"

  ingress {
    cidr = "0.0.0.0/0"
  }
}
```


## Compliant Code Examples
```terraform
resource "aws_db_security_group" "negative1" {
  name = "rds_sg"

  ingress {
    cidr = "10.0.0.0/8"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_db_security_group" "positive1" {
  name = "rds_sg"

  ingress {
    cidr = "10.0.0.0/8"
  }

  ingress {
    cidr = "0.0.0.0/0"
  }
}

```

```terraform
resource "aws_db_security_group" "positive1" {
  name = "rds_sg"

  ingress {
    cidr = "0.0.0.0/0"
  }
}

```