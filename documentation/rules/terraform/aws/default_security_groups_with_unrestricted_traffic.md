---
title: "Default security groups with unrestricted traffic"
group_id: "Terraform / AWS"
meta:
  name: "aws/default_security_groups_with_unrestricted_traffic"
  id: "46883ce1-dc3e-4b17-9195-c6a601624c73"
  display_name: "Default security groups with unrestricted traffic"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `46883ce1-dc3e-4b17-9195-c6a601624c73`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_security_group)

### Description

Default security groups in AWS act as the initial line of defense for EC2 instances, but when configured to allow unrestricted traffic (`0.0.0.0/0` for IPv4 or `::/0` for IPv6), they expose resources to potential attacks from any source on the internet. This vulnerability creates an attack surface that allows malicious actors to potentially access your instances, leading to unauthorized access, data breaches, or service disruption. To mitigate this risk, always configure security groups with specific CIDR blocks that only permit traffic from trusted sources, as shown in the following secure example:

```terraform
ingress {
  protocol  = -1
  self      = true
  from_port = 0
  to_port   = 0
  cidr_blocks = ["10.1.0.0/16"]
  ipv6_cidr_blocks = ["250.250.250.1:8451"]
}
```

## Compliant Code Examples
```terraform
resource "aws_default_security_group" "negative1" {
  vpc_id = aws_vpc.mainvpc.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
    cidr_blocks = ["10.1.0.0/16"]
    ipv6_cidr_blocks = ["250.250.250.1:8451"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.1.0.0/16"]
    ipv6_cidr_blocks = ["250.250.250.1:8451"]
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_default_security_group" "positive1" {
  vpc_id = aws_vpc.mainvpc.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_default_security_group" "positive2" {
  vpc_id = aws_vpc.mainvpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_default_security_group" "positive3" {
  vpc_id = aws_vpc.mainvpc.id

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}
```