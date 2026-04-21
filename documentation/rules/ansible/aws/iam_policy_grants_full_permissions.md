---
title: "IAM policy grants full permissions"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_policy_grants_full_permissions"
  id: "b5ed026d-a772-4f07-97f9-664ba0b116f8"
  display_name: "IAM policy grants full permissions"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `b5ed026d-a772-4f07-97f9-664ba0b116f8`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_managed_policy_module.html)

### Description

IAM managed policies must not include statements that allow all actions on all resources. Wildcard Allow statements grant unrestricted privileges, greatly increase blast radius, and raise the risk of privilege escalation or data exposure.

For Ansible tasks using the `amazon.aws.iam_managed_policy` or `iam_managed_policy` modules, examine the policy document's `Statement` entries: any statement with `Effect: "Allow"` must not have both `Action` and `Resource` set to `"*"`. This rule flags tasks where `policy.Statement[].Action == "*"` and `policy.Statement[].Resource == "*"`. Instead, scope `Action` to specific API operations and `Resource` to concrete ARNs, or apply conditions to limit access.

Secure example with scoped actions and resources:

```yaml
- name: Create IAM managed policy with scoped permissions
  amazon.aws.iam_managed_policy:
    name: ExampleReadOnlyPolicy
    policy:
      Version: "2012-10-17"
      Statement:
        - Effect: "Allow"
          Action:
            - "s3:GetObject"
            - "s3:ListBucket"
          Resource:
            - "arn:aws:s3:::example-bucket"
            - "arn:aws:s3:::example-bucket/*"
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
        Resource: SomeResource
    make_default: false
    state: present

```

```yaml
- name: Create IAM Managed Policy
  amazon.aws.iam_managed_policy:
    name: my-iam-policy
    policy_name: ManagedPolicy
    policy:
      Version: '2012-10-17'
      Statement:
      - Effect: Allow
        Action: '*'
        Resource: ec2messages:GetEndpoint
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
        Action: "*"
        Resource: "*"
    make_default: false
    state: present

```