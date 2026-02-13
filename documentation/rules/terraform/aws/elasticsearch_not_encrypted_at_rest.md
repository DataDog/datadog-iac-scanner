---
title: "Elasticsearch not encrypted at rest"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_not_encrypted_at_rest"
  id: "24e16922-4330-4e9d-be8a-caa90299466a"
  display_name: "Elasticsearch not encrypted at rest"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `24e16922-4330-4e9d-be8a-caa90299466a`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain)

### Description

 This check ensures that AWS Elasticsearch domains have encryption at rest enabled, which protects sensitive data stored in Elasticsearch indices from unauthorized access if the underlying physical storage is compromised. Without encryption at rest, data stored in Elasticsearch is vulnerable to exposure if someone gains access to the underlying storage media, potentially leading to data breaches and compliance violations.

To properly secure Elasticsearch, you must explicitly configure the encrypt_at_rest block with enabled set to true:

```
resource "aws_elasticsearch_domain" "example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
      enabled = true
  }
}
```

Insecure configurations either omit the `encrypt_at_rest` block entirely or explicitly set `enabled` to `false`.


## Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "negative1" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
      enabled = true
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "positive1" {
  domain_name           = "example"
  elasticsearch_version = "1.5"
}

resource "aws_elasticsearch_domain" "positive2" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
      enabled = false
  }
}
```