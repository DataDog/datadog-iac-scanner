---
title: "Redshift cluster logging disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/redshift_cluster_logging_disabled"
  id: "15ffbacc-fa42-4f6f-a57d-2feac7365caa"
  display_name: "Redshift cluster logging disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `15ffbacc-fa42-4f6f-a57d-2feac7365caa`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#enable)

### Description

 Amazon Redshift clusters should have logging enabled to ensure that audit and diagnostic data, such as query execution and connection attempts, are recorded and stored for security and compliance purposes. If the `logging` block is omitted, or the attribute `enable` is set to `false` in the Redshift cluster Terraform resource, as shown below, critical events may go unrecorded, making it difficult to detect unauthorized access or investigate security incidents.

```
resource "aws_redshift_cluster" "example" {
  // ... other configuration ...
  logging {
      enable = false
  }
}
```

Enabling logging with the following configuration helps ensure that activity is continuously monitored and available for review in the case of an incident.

```
logging {
    enable = true
    bucket_name = "nameOfAnExistingS3Bucket"
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
  logging {
      enable = true
      bucket_name = "nameOfAnExistingS3Bucket"
  }
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
  logging {
      enable = false
  }
}

resource "aws_redshift_cluster" "positive2" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
}
```