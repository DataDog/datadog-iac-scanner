---
title: "Redshift not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/redshift_not_encrypted"
  id: "cfdcabb0-fc06-427c-865b-c59f13e898ce"
  display_name: "Redshift not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `cfdcabb0-fc06-427c-865b-c59f13e898ce`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#encrypted)

### Description

AWS Redshift clusters store large amounts of potentially sensitive data and should be encrypted at rest to protect this information from unauthorized access if the underlying storage is compromised. When a Redshift cluster is not encrypted, all data stored within it remains in plaintext, potentially exposing customer information, business data, or other confidential information to attackers who gain access to the storage media. To properly secure your Redshift cluster, explicitly set the `encrypted` parameter to true in your Terraform configuration, as shown in the following example: 
```
resource "aws_redshift_cluster" "secure_example" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = true
}
```

## Compliant Code Examples
```terraform
resource "aws_redshift_cluster" "negative1" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = true
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_redshift_cluster" "positive1" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
}

resource "aws_redshift_cluster" "positive2" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = false
}

```