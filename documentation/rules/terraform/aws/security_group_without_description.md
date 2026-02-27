---
title: "Security group rule without description"
group_id: "Terraform / AWS"
meta:
  name: "aws/security_group_without_description"
  id: "cb3f5ed6-0d18-40de-a93d-b3538db31e8c"
  display_name: "Security group rule without description"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `cb3f5ed6-0d18-40de-a93d-b3538db31e8c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group#description)

### Description

It is a best practice for AWS security groups to include a meaningful `description` attribute in their Terraform configuration, such as in the following example:

```
description = "Allow TLS inbound traffic"
```

Omitting the description field, as shown below, can lead to confusion and hinder effective management or auditing of security groups, especially in environments with many resources:

```
resource "aws_security_group" "allow_tls" {
  name   = "allow_tls"
  vpc_id = aws_vpc.main.id
  // missing description
  ...
}
```

Without clear descriptions, security teams may struggle to quickly identify the purpose of a group, increasing the risk of misconfigurations and delayed incident response.

## Compliant Code Examples
```terraform
resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [aws_vpc.main.cidr_block]
    ipv6_cidr_blocks = [aws_vpc.main.ipv6_cidr_block]
  }

  tags = {
    Name = "allow_tls"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [aws_vpc.main.cidr_block]
    ipv6_cidr_blocks = [aws_vpc.main.ipv6_cidr_block]
  }

  tags = {
    Name = "allow_tls"
  }
}

```