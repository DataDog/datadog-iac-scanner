---
title: "Dynamodb VPC endpoint without route table association"
group_id: "Terraform / AWS"
meta:
  name: "aws/dynamodb_vpc_endpoint_without_route_table_association"
  id: "0bc534c5-13d1-4353-a7fe-b8665d5c1d7d"
  display_name: "Dynamodb VPC endpoint without route table association"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `0bc534c5-13d1-4353-a7fe-b8665d5c1d7d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_endpoint#vpc_id)

### Description

 AWS VPC endpoints for DynamoDB provide secure and private connectivity between VPC resources and DynamoDB without traversing the public internet. For a VPC endpoint to function correctly, it must be associated with one or more route tables using the `aws_route_table_association` resource, which ensures the correct routes (`route_table_id` and `subnet_id`) direct DynamoDB traffic through the endpoint. If this association is missing, instances within the VPC will not be able to route requests to DynamoDB over the VPC endpoint, potentially forcing traffic through the public internet or causing connectivity failures. This misconfiguration can expose sensitive data to unnecessary network risk and violates best practices for securing internal AWS service communications.


## Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

locals {
  s3_prefix_list_cidr_block = "3.218.183.128/25"
}
resource "aws_vpc" "main2" {
  cidr_block = "192.168.100.0/24"
  enable_dns_support = true
}

resource "aws_subnet" "private-subnet2" {
  vpc_id     = aws_vpc.main2.id
  cidr_block = "192.168.100.128/25"

  tags = {
    Name = "private-subnet"
  }
}

resource "aws_route_table" "private-rtb2" {
  vpc_id = aws_vpc.main2.id

  tags = {
    Name = "private-rtb"
  }
}

resource "aws_route_table_association" "private-rtb-assoc2" {
  subnet_id      = aws_subnet.private-subnet2.id
  route_table_id = aws_route_table.private-rtb2.id
}

resource "aws_vpc_endpoint" "dynamodb-vpce-gw2" {
  vpc_id       = aws_vpc.main2.id
  service_name = "com.amazonaws.us-east-1.dynamodb"
}

resource "aws_network_acl" "allow-public-outbound-nacl2" {
  vpc_id = aws_vpc.main.id
  subnet_ids = [aws_subnet.private-subnet2.id]

  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = local.s3_prefix_list_cidr_block
    from_port  = 443
    to_port    = 443
  }

  tags = {
    Name = "allow-public-outbound-nacl"
  }
}

resource "aws_security_group" "allow-public-outbound-sg2" {
  name        = "allow-public-outbound-sg"
  description = "Allow HTTPS outbound traffic"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.s3_prefix_list_cidr_block]
  }

}

data "aws_ami" "ubuntu2" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "test2" {
  ami = data.aws_ami.ubuntu2.id
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.allow-public-outbound-sg2.id]
  subnet_id = aws_subnet.private-subnet2.id
}

resource "aws_dynamodb_table" "basic-dynamodb-table2" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "UserId"
  range_key      = "GameTitle"

  attribute {
    name = "UserId"
    type = "S"
  }

  attribute {
    name = "GameTitle"
    type = "S"
  }
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

locals {
  s3_prefix_list_cidr_block = "3.218.183.128/25"
}
resource "aws_vpc" "main" {
  cidr_block = "192.168.100.0/24"
  enable_dns_support = true
}

resource "aws_subnet" "private-subnet" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "192.168.100.128/25"

  tags = {
    Name = "private-subnet"
  }
}

resource "aws_route_table" "private-rtb" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "private-rtb"
  }
}

resource "aws_vpc_endpoint" "dynamodb-vpce-gw" {
  vpc_id       = aws_vpc.main.id
  service_name = "com.amazonaws.us-east-1.dynamodb"
}

resource "aws_network_acl" "allow-public-outbound-nacl" {
  vpc_id = aws_vpc.main.id
  subnet_ids = [aws_subnet.private-subnet.id]

  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = local.s3_prefix_list_cidr_block
    from_port  = 443
    to_port    = 443
  }

  tags = {
    Name = "allow-public-outbound-nacl"
  }
}

resource "aws_security_group" "allow-public-outbound-sg" {
  name        = "allow-public-outbound-sg"
  description = "Allow HTTPS outbound traffic"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.s3_prefix_list_cidr_block]
  }

}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_instance" "test" {
  ami = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.allow-public-outbound-sg.id]
  subnet_id = aws_subnet.private-subnet.id
}

resource "aws_dynamodb_table" "basic-dynamodb-table" {
  name           = "GameScores"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "UserId"
  range_key      = "GameTitle"

  attribute {
    name = "UserId"
    type = "S"
  }

  attribute {
    name = "GameTitle"
    type = "S"
  }
}

```