---
title: "RDS associated with public subnet"
group_id: "Terraform / AWS"
meta:
  name: "aws/rds_associated_with_public_subnet"
  id: "2f737336-b18a-4602-8ea0-b200312e1ac1"
  display_name: "RDS associated with public subnet"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `2f737336-b18a-4602-8ea0-b200312e1ac1`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#db_subnet_group_name)

### Description

Amazon RDS instances should not be associated with public subnets to prevent potential unauthorized access from the internet. When an RDS instance is placed in a subnet group containing a public subnet (with a CIDR such as `0.0.0.0/0)`, it creates an attack vector for malicious actors to exploit your database. 

Instead, RDS instances should only be deployed in private subnets with specific CIDR blocks. In the secure example, subnets use specific CIDR blocks such as `172.2.0.0/24` and `176.2.0.0/24`, while the vulnerable example uses `0.0.0.0/0` which allows traffic from any IP address. Properly securing your database network configuration helps prevent data breaches and unauthorized access to sensitive information.

## Compliant Code Examples
```terraform
resource "aws_db_instance" "negative1" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "negative1.mysql5.7"
  skip_final_snapshot  = true
  db_subnet_group_name = aws_db_subnet_group.subnetGroup3.name
}

resource "aws_db_subnet_group" "subnetGroup3" {
  name       = "main"
  subnet_ids = [aws_subnet.frontend3.id, aws_subnet.backend3.id]

  tags = {
    Name = "My DB subnet group"
  }
}

resource "aws_subnet" "frontend3" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  cidr_block = "172.2.0.0/24"
}


resource "aws_subnet" "backend3" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr2.vpc_id
  cidr_block = "176.2.0.0/24"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_db_instance" "positive2" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "positive2.mysql5.7"
  skip_final_snapshot  = true
  db_subnet_group_name = "subnetGroup2"
}

resource "aws_db_subnet_group" "subnetGroup2" {
  name       = "main"
  subnet_ids = [aws_subnet.frontend2.id, aws_subnet.backend2.id]

  tags = {
    Name = "My DB subnet group"
  }
}

resource "aws_subnet" "frontend2" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  cidr_block = "172.2.0.0/24"
}


resource "aws_subnet" "backend2" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  cidr_block = "0.0.0.0/0"
}

```

```terraform
resource "aws_db_instance" "positive1" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "positive1.mysql5.7"
  skip_final_snapshot  = true
  db_subnet_group_name = aws_db_subnet_group.subnetGroup.name
}

resource "aws_db_subnet_group" "subnetGroup" {
  name       = "main"
  subnet_ids = [aws_subnet.frontend.id, aws_subnet.backend.id]

  tags = {
    Name = "My DB subnet group"
  }
}

resource "aws_subnet" "frontend" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  cidr_block = "172.2.0.0/24"
}


resource "aws_subnet" "backend" {
  vpc_id     = aws_vpc_ipv4_cidr_block_association.secondary_cidr.vpc_id
  cidr_block = "0.0.0.0/0"
}

```