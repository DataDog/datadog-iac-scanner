---
title: "Instance with no VPC"
group_id: "Terraform / AWS"
meta:
  name: "aws/instance_with_no_vpc"
  id: "a31a5a29-718a-4ff4-8001-a69e5e4d029e"
  display_name: "Instance with no VPC"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a31a5a29-718a-4ff4-8001-a69e5e4d029e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance)

### Description

Amazon EC2 instances should always be provisioned within a Virtual Private Cloud (VPC) to leverage the network isolation, traffic filtering, and granular access controls that VPCs provide. If EC2 instances are created without specifying a `subnet_id` or `vpc_security_group_ids` (as shown in the configuration below), they may default to legacy EC2-Classic networks or lack critical network restrictions, increasing the risk of unauthorized access and exposure to attacks. Using a VPC ensures all traffic to and from instances can be centrally managed, monitored, and audited, reducing the attack surface.

Insecure example:
```
resource "aws_instance" "example" {
  ami           = "ami-003634241a8fcdec0"
  instance_type = "t2.micro"
}
```

Secure example:
```
resource "aws_instance" "example" {
  ami                    = "ami-003634241a8fcdec0"
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.example.id
  vpc_security_group_ids = [aws_security_group.example.id]
}
```

## Compliant Code Examples
```terraform
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  name = "single-instance"

  ami                    = "ami-ebd02392"
  instance_type          = "t2.micro"
  key_name               = "user1"
  monitoring             = true
  vpc_security_group_ids = ["sg-12345678"]
  subnet_id              = "subnet-eddcdzz4"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
resource "aws_instance" "negative1" {
  ami = "ami-003634241a8fcdec0"

  instance_type = "t2.micro"

  vpc_security_group_ids = ["aws_security_group.instance.id"]

}

```
## Non-Compliant Code Examples
```terraform
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  name = "single-instance"

  ami                    = "ami-ebd02392"
  instance_type          = "t2.micro"
  key_name               = "user1"
  monitoring             = true
  subnet_id              = "subnet-eddcdzz4"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
resource "aws_instance" "positive1" {
  ami = "ami-003634241a8fcdec0"

  instance_type = "t2.micro"

}
```