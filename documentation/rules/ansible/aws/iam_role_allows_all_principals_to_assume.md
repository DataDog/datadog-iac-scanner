---
title: "IAM Role Allows All Principals To Assume"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_role_allows_all_principals_to_assume"
  id: "babdedcf-d859-43da-9a7b-6d72e661a8fd"
  display_name: "IAM Role Allows All Principals To Assume"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `babdedcf-d859-43da-9a7b-6d72e661a8fd`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_managed_policy_module.html)

### Description

Specifying the account root or an entire AWS account as a principal (ARNs that end with ":root") grants every identity in that account the ability to assume the role or act as that principal, increasing the risk of privilege escalation, lateral movement, and unauthorized access if any identity is compromised. This rule checks Ansible tasks using the `community.aws.iam_managed_policy` or `iam_managed_policy` modules and flags policy statements where `policy.Statement[].Principal.AWS` contains `:root`. Principal values must be explicit and least-privileged—use specific IAM role or user ARNs or service principals instead of account-root ARNs (or wildcards); resources with `Principal.AWS` containing `:root` will be flagged. Secure example with an explicit principal:

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/SpecificRole"
      },
      "Action": "sts:AssumeRole"
    }
  ],
  "Version": "2012-10-17"
}
```

## Compliant Code Examples
```yaml
- name: Create IAM Managed Policy
  community.aws.iam_managed_policy:
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
  community.aws.iam_managed_policy:
    policy_name: "ManagedPolicy"
    policy:
      Version: "2012-10-17"
      Statement:
      - Effect: "Allow"
        Action: "logs:CreateLogGroup"
        Resource: "*"
        Principal:
          AWS: "arn:aws:iam::root"
    make_default: false
    state: present
- name: Create2 IAM Managed Policy
  community.aws.iam_managed_policy:
    policy_name: "ManagedPolicy2"
    policy: >
      {
        "Version": "2012-10-17",
        "Statement":[{
          "Effect": "Allow",
          "Action": "logs:PutRetentionPolicy",
          "Resource": "*",
          "Principal" : { "AWS" : "arn:aws:iam::root" }
        }]
      }
    only_version: true
    state: present

```