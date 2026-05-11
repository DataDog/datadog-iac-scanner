---
title: "Secrets Manager secret without KMS"
group_id: "Terraform / AWS"
meta:
  name: "aws/secretsmanager_secret_without_kms"
  id: "terraform-aws-secretsmanager-secret-without-kms"
  display_name: "Secrets Manager secret without KMS"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-aws-secretsmanager-secret-without-kms{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id)

### Description

By default, AWS Secrets Manager encrypts secrets using the default AWS-managed key, which may not provide the desired level of control over key rotation, access policies, or auditability. Without explicitly specifying a `kms_key_id` in your Terraform resource, as shown below, secrets will not use a customer-managed AWS KMS key (CMK) for encryption:

```
resource "aws_secretsmanager_secret" "example" {
  name = "example"
}
```

This misconfiguration can increase the exposure of sensitive data and limit your ability to implement strict access controls. To reduce risk, explicitly provide a `kms_key_id` attribute referencing a CMK:

```
resource "aws_secretsmanager_secret" "example" {
  name       = "example"
  kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
```

## Compliant Code Examples
```terraform
resource "aws_secretsmanager_secret" "example" {
  name = "example"
  kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_secretsmanager_secret" "example" {
  name = "example"
}

```