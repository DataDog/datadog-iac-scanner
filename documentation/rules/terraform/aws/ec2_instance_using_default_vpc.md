---
title: "EC2 instance using default VPC"
group_id: "Terraform / AWS"
meta:
  name: "aws/ec2_instance_using_default_vpc"
  id: "7e4a6e76-568d-43ef-8c4e-36dea481bff1"
  display_name: "EC2 instance using default VPC"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `7e4a6e76-568d-43ef-8c4e-36dea481bff1`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#subnet_id)

### Description

This check ensures that Amazon EC2 instances are not deployed within the default VPC (`aws_vpc.default`) in AWS environments. Default VPCs are automatically created by AWS and often have broader, pre-configured network permissions and less restrictive security controls, increasing the attack surface and risk of unauthorized access. By explicitly defining and using custom VPCs (for example, `aws_vpc.main`), organizations can enforce tailored network segmentation and security group rules, reducing the likelihood of exploitation due to overly permissive defaults.

## Compliant Code Examples
```terraform
resource "aws_instance" "negative1" {
  ami = "ami-003634241a8fcdec0"

  instance_type = "t2.micro"

  subnet_id   = aws_subnet.my_subnet2.id

}

resource "aws_subnet" "my_subnet2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Main"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_instance" "positive1" {
  ami = "ami-003634241a8fcdec0"

  instance_type = "t2.micro"

  subnet_id   = aws_subnet.my_subnet.id

}

resource "aws_subnet" "my_subnet" {
  vpc_id     = aws_vpc.default.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Main"
  }
}

```