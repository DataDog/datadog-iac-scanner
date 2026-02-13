---
title: "Elasticsearch domain not encrypted node to node"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_domain_not_encrypted_node_to_node"
  id: "967eb3e6-26fc-497d-8895-6428beb6e8e2"
  display_name: "Elasticsearch domain not encrypted node to node"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `967eb3e6-26fc-497d-8895-6428beb6e8e2`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#node_to_node_encryption)

### Description

Enabling node-to-node encryption for an Elasticsearch domain ensures that data transferred between nodes in the Elasticsearch cluster is securely encrypted, preventing unauthorized access to data in transit. If the `node_to_node_encryption` block is omitted, sensitive data could be intercepted by attackers during communication between cluster nodes. To secure the domain, configure:

```
node_to_node_encryption {
  enabled = true
}
```

This ensures that all internal communications within the cluster is encrypted, reducing the risk of data exposure.

## Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "negative1" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  cluster_config {
    instance_type = "r4.large.elasticsearch"
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  node_to_node_encryption {
    enabled = true
  }

  tags = {
    Domain = "TestDomain"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "positive1" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  cluster_config {
    instance_type = "r4.large.elasticsearch"
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  node_to_node_encryption {
    enabled = false
  }

  tags = {
    Domain = "TestDomain"
  }
}

```

```terraform
resource "aws_elasticsearch_domain" "positive1" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  cluster_config {
    instance_type = "r4.large.elasticsearch"
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  tags = {
    Domain = "TestDomain"
  }
}

```