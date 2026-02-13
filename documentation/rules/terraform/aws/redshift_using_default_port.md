---
title: "Redshift using default port"
group_id: "Terraform / AWS"
meta:
  name: "aws/redshift_using_default_port"
  id: "41abc6cc-dde1-4217-83d3-fb5f0cc09d8f"
  display_name: "Redshift using default port"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `41abc6cc-dde1-4217-83d3-fb5f0cc09d8f`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#port)

### Description

 Amazon Redshift clusters listen on a default port (`5439`) unless otherwise specified using the `port` attribute in Terraform. Using the default port increases the risk of brute-force and automated attacks, as malicious actors frequently scan for commonly used service ports. Setting a custom port adds an obscurity layer by making the service less predictable to attackers, thereby reducing its exposure to opportunistic network attacks.


## Compliant Code Examples
```terraform
resource "aws_redshift_cluster" "negative1" {
  cluster_identifier    = "tf-redshift-cluster"
  database_name         = "mydb"
  master_username       = "foo"
  master_password       = "Mustbe8characters"
  node_type             = "dc1.large"
  cluster_type          = "single-node"
  publicly_accessible   = false
  port                  = 1150
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_redshift_cluster" "positive2" {
  cluster_identifier    = "tf-redshift-cluster"
  database_name         = "mydb"
  master_username       = "foo"
  master_password       = "Mustbe8characters"
  node_type             = "dc1.large"
  cluster_type          = "single-node"
  publicly_accessible   = false
  port                  = 5439
}

```

```terraform
resource "aws_redshift_cluster" "positive1" {
  cluster_identifier    = "tf-redshift-cluster"
  database_name         = "mydb"
  master_username       = "foo"
  master_password       = "Mustbe8characters"
  node_type             = "dc1.large"
  cluster_type          = "single-node"
  publicly_accessible   = false
}

```