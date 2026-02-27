---
title: "VPC subnet assigns public IP"
group_id: "Terraform / AWS"
meta:
  name: "aws/vpc_subnet_assigns_public_ip"
  id: "52f04a44-6bfa-4c41-b1d3-4ae99a2de05c"
  display_name: "VPC subnet assigns public IP"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `52f04a44-6bfa-4c41-b1d3-4ae99a2de05c`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet#map_public_ip_on_launch)

### Description

This check ensures that AWS VPC subnets do not automatically assign public IP addresses by verifying the value of the `map_public_ip_on_launch` attribute. If this attribute is set to `true`, as shown in `map_public_ip_on_launch = true`, instances launched in the subnet will receive public IPs by default, potentially exposing them to the public internet. Leaving this misconfiguration unaddressed increases the risk of unauthorized access, data breaches, and external attacks.

## Compliant Code Examples
```terraform
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.7.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

  map_public_ip_on_launch = false
  enable_nat_gateway      = true
  enable_vpn_gateway      = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
resource "aws_vpc" "main3" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "negative2" {
  vpc_id     = aws_vpc.main3.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Negative2"
  }

  map_public_ip_on_launch = false
}

```

```terraform
resource "aws_vpc" "main2" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "negative1" {
  vpc_id     = aws_vpc.main2.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Negative1"
  }
}

```
## Non-Compliant Code Examples
```terraform
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.7.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

  map_public_ip_on_launch = true
  enable_nat_gateway      = true
  enable_vpn_gateway      = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.7.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = true

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

```

```terraform
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "positive" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Positive"
  }

  map_public_ip_on_launch = true
}

```