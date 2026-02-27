---
title: "CloudWatch log group without KMS"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_log_group_not_encrypted"
  id: "0afbcfe9-d341-4b92-a64c-7e6de0543879"
  display_name: "CloudWatch log group without KMS"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `0afbcfe9-d341-4b92-a64c-7e6de0543879`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group)

### Description

AWS CloudWatch log groups should use KMS encryption to protect sensitive log data at rest. When the `aws_cloudwatch_log_group` resource is defined without the `kms_key_id` attribute, as in the following example, logs are stored unencrypted or with default encryption, making them vulnerable to unauthorized access if AWS accounts or storage is compromised:

```
resource "aws_cloudwatch_log_group" "negative1" {
  name = "Yada"
  retention_in_days = 1
}
```

By specifying the `kms_key_id` attribute, you ensure that log data is encrypted with a customer-managed AWS KMS key, reducing the risk of data exposure.

## Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_group" "negative1" {
  name = "Yada"

  tags = {
    Environment = "production"
    Application = "serviceA"
  }

  retention_in_days = 1
  kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_group" "negative1" {
  name = "Yada"

  tags = {
    Environment = "production"
    Application = "serviceA"
  }

  retention_in_days = 1
}

```