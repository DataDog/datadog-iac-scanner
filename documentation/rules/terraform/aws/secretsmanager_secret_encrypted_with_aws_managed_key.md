---
title: "Secrets Manager secret encrypted with AWS-managed key"
group_id: "Terraform / AWS"
meta:
  name: "aws/secretsmanager_secret_encrypted_with_aws_managed_key"
  id: "b0d3ef3f-845d-4b1b-83d6-63a5a380375f"
  display_name: "Secrets Manager secret encrypted with AWS-managed key"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `b0d3ef3f-845d-4b1b-83d6-63a5a380375f`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id)

### Description

 AWS Secrets Manager secrets should be encrypted with customer-managed KMS keys rather than the default AWS-managed keys. Relying on AWS managed keys limits an organization's ability to control, rotate, and audit encryption keys, which are important factors in enforcing robust security policies and compliance requirements. Without customer-managed KMS keys, there may be a greater risk of unauthorized access or insufficient key lifecycle management. If left unaddressed, sensitive information stored in Secrets Manager could be compromised due to weaker or less transparent key management practices.


## Compliant Code Examples
```terraform
resource "aws_secretsmanager_secret" "test222" {
  name       = "test-cloudrail-1"
  kms_key_id = "alias/MyAlias"
}


```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

data "aws_kms_key" "by_alias" {
  key_id = "alias/aws/secretsmanager"
}

resource "aws_secretsmanager_secret" "test" {
  name       = "test-cloudrail-1"
  kms_key_id = data.aws_kms_key.by_alias.arn
}

```

```terraform
resource "aws_secretsmanager_secret" "test2" {
  name       = "test-cloudrail-1"
  kms_key_id = "alias/aws/secretsmanager"
}

```