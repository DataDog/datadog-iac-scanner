---
title: "Fine-grained access control disabled for OpenSearch/Elasticsearch"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_no_finegrain_access_control"
  id: "b4c6d7e8-f9a1-4bcd-89ef-01234abcd567"
  display_name: "Fine-grained access control disabled for OpenSearch/Elasticsearch"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `b4c6d7e8-f9a1-4bcd-89ef-01234abcd567`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/opensearch_domain#advanced_security_options)

### Description

 Fine-grained access control in AWS OpenSearch and Elasticsearch domains enables administrators to restrict access to specific indices, documents, and fields based on user permissions, significantly enhancing security. Without this control enabled, your domain could be vulnerable to unauthorized access, data breaches, and potential exfiltration of sensitive information stored in your search clusters. Both the `enabled` and `internal_user_database_enabled` parameters must be set to `true` within the `advanced_security_options` block to properly secure the domain, as shown in the following secure configuration:

```terraform
resource "aws_opensearch_domain" "good_example" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
  }
}
```


## Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "good_example" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = true # ✅ Fine-grained access control is enabled
    internal_user_database_enabled = true # ✅ Internal user database is enabled
  }
}

```

```terraform
resource "aws_opensearch_domain" "good_example" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = true # ✅ Fine-grained access control is enabled
    internal_user_database_enabled = true # ✅ Internal user database is enabled
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_opensearch_domain" "bad_example" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = false # ❌ Fine-grained access control is disabled
    internal_user_database_enabled = false # ❌ Internal user database is disabled
  }
}

resource "aws_elasticsearch_domain" "bad_example2" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = false # ❌ Fine-grained access control is disabled
    internal_user_database_enabled = false # ❌ Internal user database is disabled
  }
}

resource "aws_elasticsearch_domain" "bad_example3" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
  }
}

resource "aws_elasticsearch_domain" "bad_example4" {
  domain_name = "example"

  advanced_security_options {
    enabled                        = false
    internal_user_database_enabled = true
  }
}

resource "aws_elasticsearch_domain" "bad_example5" {
  domain_name = "example"

                                              # ❌ No advanced_security_options block
}

```