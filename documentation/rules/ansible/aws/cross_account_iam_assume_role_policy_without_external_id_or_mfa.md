---
title: "Cross-account IAM assume role policy without ExternalId or MFA"
group_id: "Ansible / AWS"
meta:
  name: "aws/cross_account_iam_assume_role_policy_without_external_id_or_mfa"
  id: "ansible-aws-cross-account-iam-assume-role-policy-without-externalid-or-mfa"
  display_name: "Cross-account IAM assume role policy without ExternalId or MFA"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `ansible-aws-cross-account-iam-assume-role-policy-without-externalid-or-mfa`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_role_module.html#parameter-assume_role_policy_document)

### Description

Cross-account IAM role trust policies that allow `sts:AssumeRole` to external principals must require an `ExternalId` or MFA to prevent unintended or unauthorized access from third-party accounts. Without an `ExternalId` or a `Condition` requiring MFA, an external principal (including other-account root principals) that can assume the role may gain access to sensitive resources or perform privileged actions.

In Ansible `amazon.aws.iam_role` and `iam_role` tasks, the `assume_role_policy_document` `Statement` with `Effect: Allow` and `Action: sts:AssumeRole` that names a cross-account `Principal` (for example, an ARN that includes another account or `:root`) must include a `Condition` containing either `sts:ExternalId` (for example, `StringEquals`) or `aws:MultiFactorAuthPresent` set to `true`. Resources missing the required `Condition` or that allow cross-account assume-role without `ExternalId` or MFA are flagged.

Secure trust policy examples:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "your-external-id-value" }
      }
    }
  ]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": { "aws:MultiFactorAuthPresent": "true" }
      }
    }
  ]
}
```

## Compliant Code Examples
```yaml
- name: Create a role with description and tags4
  amazon.aws.iam_role:
    name: mynewrole4
    assume_role_policy_document: >
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "sts:AssumeRole",
            "Principal": {
              "AWS": "arn:aws:iam::987654321145:root"
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "",
            "Condition": {
              "StringEquals": {
                "sts:ExternalId": "98765"
              }
            }
          }
        ]
      }
    description: This is My New Role
    tags:
      env: dev

```

```yaml
- name: Create a role with description and tags5
  amazon.aws.iam_role:
    name: mynewrole5
    assume_role_policy_document: >
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "sts:AssumeRole",
            "Principal": {
              "AWS": "arn:aws:iam::987654321145:root"
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "",
            "Condition": {
              "Bool": {
                "aws:MultiFactorAuthPresent": "true"
              }
            }
          }
        ]
      }
    description: This is My New Role
    tags:
      env: dev

```
## Non-Compliant Code Examples
```yaml
- name: Create a role with description and tags2
  amazon.aws.iam_role:
    name: mynewrole2
    assume_role_policy_document: >
      {
        "Version": "2012-10-17",
        "Statement": {
          "Action": "sts:AssumeRole",
          "Principal": {
              "AWS": "arn:aws:iam::987654321145:root"
          },
          "Effect": "Allow",
          "Resource": "*",
          "Sid": "",
          "Condition": {
            "Bool": {
                "aws:MultiFactorAuthPresent": "false"
            }
          }
        }
      }
    description: This is My New Role
    tags:
      env: dev

```

```yaml
- name: Create a role with description and tags3
  amazon.aws.iam_role:
    name: mynewrole3
    assume_role_policy_document: >
      {
        "Version": "2012-10-17",
        "Statement": {
            "Action": "sts:AssumeRole",
            "Principal": {
              "AWS": "arn:aws:iam::987654321145:root"
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "",
            "Condition": {
              "StringEquals": {
                "sts:ExternalId": ""
              }
            }
        }
      }
    description: This is My New Role
    tags:
      env: dev

```

```yaml
- name: Create a role with description and tags
  amazon.aws.iam_role:
    name: mynewrole
    assume_role_policy_document: >
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "sts:AssumeRole",
            "Principal": {
              "AWS": "arn:aws:iam::987654321145:root"
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": ""
          }
        ]
      }
    description: This is My New Role
    tags:
      env: dev

```