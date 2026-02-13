---
title: "Elasticsearch encryption with KMS disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_encryption_with_kms_is_disabled"
  id: "7af2f4a3-00d9-47f3-8d15-ca0888f4e5b2"
  display_name: "Elasticsearch encryption with KMS disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `7af2f4a3-00d9-47f3-8d15-ca0888f4e5b2`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain)

### Description

Elasticsearch domains should use AWS Key Management Service (KMS) for encryption at rest to provide enhanced security. While enabling basic encryption at rest is important, not specifying a KMS key ID means Elasticsearch will use default AWS-managed keys rather than customer-managed keys, reducing your control over the encryption process. Without KMS encryption, sensitive data stored in Elasticsearch could be at risk if unauthorized access to the storage media occurs.

To properly implement KMS encryption, ensure the `encrypt_at_rest` block includes both `enabled = true` and a specific `kms_key_id`, as shown below:

```terraform
encrypt_at_rest {
    enabled = true
    kms_key_id = "your-kms-key-id"
}
```

## Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "negative1" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
      enabled = true
      kms_key_id = "some-key-id"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "positive1" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  encrypt_at_rest {
      enabled = true
  }
}
```