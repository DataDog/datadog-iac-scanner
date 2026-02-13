---
title: "IAM access key is exposed"
group_id: "Terraform / AWS"
meta:
  name: "aws/iam_access_key_is_exposed"
  id: "7081f85c-b94d-40fd-8b45-a4f1cac75e46"
  display_name: "IAM access key is exposed"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `7081f85c-b94d-40fd-8b45-a4f1cac75e46`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key)

### Description

IAM access keys should never be created or kept active for AWS root user accounts, as specified by the `user = "root"` and `status = "Active"` attributes in a Terraform `aws_iam_access_key` resource block. Allowing active access keys for root users significantly increases the attack surface and exposes highly privileged credentials to potential misuse or compromise, since the root account has unrestricted control over the entire AWS environment. To ensure security, root accounts should have all access keys disabled. For example:

```
resource "aws_iam_access_key" "secure_root" {
  user   = "root"
  status = "Inactive"
}
```

## Compliant Code Examples
```terraform
resource "aws_iam_access_key" "negative1" {
  user = "some-user"
}

resource "aws_iam_access_key" "negative2" {
  user = "some-user"
  status = "Active"
}

resource "aws_iam_access_key" "negative3" {
  user = "root"
  status = "Inactive"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_access_key" "positive1" {
  user = "root"
  status = "Active"
}

resource "aws_iam_access_key" "positive2" {
  user = "root"
}

```