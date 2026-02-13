---
title: "VPC default security group accepts all traffic"
group_id: "Terraform / AWS"
meta:
  name: "aws/vpc_default_security_group_accepts_all_traffic"
  id: "9a4ef195-74b9-4c58-b8ed-2b2fe4353a75"
  display_name: "VPC default security group accepts all traffic"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `9a4ef195-74b9-4c58-b8ed-2b2fe4353a75`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_security_group)

### Description

 Default security groups are automatically created when a VPC is created and allow all inbound traffic from resources assigned to the same security group, as well as all outbound traffic by default. This creates a significant security vulnerability as it allows unrestricted network access between resources, potentially enabling lateral movement during a breach. 

Secure implementation should not define open ingress/egress rules, as in the following example:
```
resource "aws_default_security_group" "default2" {
  vpc_id = aws_vpc.mainvpc2.id
}
```

Avoid explicitly configuring rules that allow all traffic, such as in the following example:
```
ingress = [{
  protocol  = -1
  self      = true
  from_port = 0
  to_port   = 0
}]
```


## Compliant Code Examples
```terraform
resource "aws_vpc" "mainvpc2" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_default_security_group" "default2" {
  vpc_id = aws_vpc.mainvpc2.id
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_vpc" "mainvpc3" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_default_security_group" "default3" {
  vpc_id = aws_vpc.mainvpc3.id

  ingress = [
    {
      protocol  = -1
      self      = true
      from_port = 0
      to_port   = 0
      ipv6_cidr_blocks = ["::/0"]
    }
  ]

  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

```

```terraform
resource "aws_vpc" "mainvpc" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.mainvpc.id

  ingress = [
    {
      protocol  = -1
      self      = true
      from_port = 0
      to_port   = 0
    }
  ]

  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
    }
  ]
}

```