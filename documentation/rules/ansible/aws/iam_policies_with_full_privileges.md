---
title: "IAM policies with full privileges"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_policies_with_full_privileges"
  id: "e401d614-8026-4f4b-9af9-75d1197461ba"
  display_name: "IAM policies with full privileges"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `e401d614-8026-4f4b-9af9-75d1197461ba`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_managed_policy_module.html)

### Description

IAM policies must not grant full administrative privileges (Allow for all actions on all resources). Such statements enable privilege escalation and allow any principal with the policy to access, modify, or delete resources account-wide. For Ansible managed policy resources (modules `amazon.aws.iam_managed_policy` and `iam_managed_policy`), inspect the `policy` document's `Statement` entries. Ensure no `Statement` has `Effect: Allow` where `Action` is `"*"` and `Resource` is `"*"`. Define explicit action lists and restrict `Resource` to specific ARNs, or use condition keys to enforce least privilege. If full admin rights are truly required, attach AWS-managed administrative policies only to trusted admin roles or groups. Statements matching `Effect` set to `Allow` with both `Action` set to `'*'` and `Resource` set to `'*'` are flagged.

Secure example with explicit actions and narrowed resources:

```yaml
- name: Create limited S3 read policy
  amazon.aws.iam_managed_policy:
    name: ReadOnlyS3Policy
    policy:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Action:
            - s3:ListBucket
            - s3:GetObject
          Resource:
            - arn:aws:s3:::my-bucket
            - arn:aws:s3:::my-bucket/*
```

## Compliant Code Examples
```yaml
- name: Create IAM Managed Policy
  amazon.aws.iam_managed_policy:
    name: my-iam-policy
    policy_name: ManagedPolicy
    policy:
      Version: '2012-10-17'
      Statement:
      - Effect: Allow
        Action: logs:CreateLogGroup
        Resource: '*'
    make_default: false
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: Create IAM Managed Policy
  amazon.aws.iam_managed_policy:
    name: my-iam-policy
    policy_name: "ManagedPolicy"
    policy:
      Version: "2012-10-17"
      Statement:
      - Effect: "Allow"
        Action: ["*"]
        Resource: "*"
    make_default: false
    state: present

```