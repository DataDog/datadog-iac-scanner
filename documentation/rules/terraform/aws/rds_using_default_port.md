---
title: "RDS using default port"
group_id: "Terraform / AWS"
meta:
  name: "aws/rds_using_default_port"
  id: "bca7cc4d-b3a4-4345-9461-eb69c68fcd26"
  display_name: "RDS using default port"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `bca7cc4d-b3a4-4345-9461-eb69c68fcd26`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#port)

### Description

Databases provisioned using Amazon RDS should not be configured to use default ports—for example, MySQL/Aurora/MariaDB (3306), PostgreSQL (5432), Oracle (1521), or SQL Server (1433)—as these are well-known and commonly targeted by attackers during automated scans and brute-force attacks. By specifying the port attribute in a Terraform configuration (for example, `port = 3306`), the database remains easily discoverable by attackers who search for open default ports, increasing the risk of unauthorized access and exploitation. Altering the port to a non-standard value (for example, `port = 3307`) reduces the likelihood of automated attacks by introducing a layer of obscurity, helping to protect the database from opportunistic threats. If left unaddressed, using the default port can lead to a higher exposure risk and potential data breaches, even if other security controls are in place.

## Compliant Code Examples
```terraform
resource "aws_db_instance" "negative3" {
  allocated_storage    = 10
  engine               = "oracle-ee"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  skip_final_snapshot  = true
  port                 = 1522
}

```

```terraform
resource "aws_db_instance" "negative2" {
  allocated_storage    = 10
  engine               = "postgres"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  skip_final_snapshot  = true
  port                 = 5433
}

```

```terraform
resource "aws_db_instance" "negative1" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = aws_elasticache_parameter_group.default.id
  skip_final_snapshot  = true
  port                 = 3307
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_db_instance" "positive2" {
  allocated_storage    = 10
  engine               = "postgres"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  skip_final_snapshot  = true
  port                 = 5432
}

```

```terraform
resource "aws_db_instance" "positive3" {
  allocated_storage    = 10
  engine               = "oracle-ee"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  skip_final_snapshot  = true
  port                 = 1521
}

```

```terraform
resource "aws_db_instance" "positive4" {
  allocated_storage    = 10
  engine               = "sqlserver-ee"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  skip_final_snapshot  = true
  port                 = 1433
}

```