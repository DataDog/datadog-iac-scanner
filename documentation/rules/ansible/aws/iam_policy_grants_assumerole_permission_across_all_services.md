---
title: "IAM policy grants 'AssumeRole' permission across all services"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_policy_grants_assumerole_permission_across_all_services"
  id: "12a7a7ce-39d6-49dd-923d-aeb4564eb66c"
  display_name: "IAM policy grants 'AssumeRole' permission across all services"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}12a7a7ce-39d6-49dd-923d-aeb4564eb66c{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/iam_managed_policy_module.html)

### Description

Policy statements that use a wildcard principal (`*`) with `Effect` set to `Allow` grant trust or permissions to any AWS principal. This can enable unauthorized accounts or external services to assume roles or perform actions, increasing the risk of privilege escalation and data exposure.

In Ansible resources `amazon.aws.iam_managed_policy` and `iam_managed_policy`, check the `policy.Statement[].Effect` and `policy.Statement[].Principal.AWS` properties. Statements must not have an `Allow` effect combined with `Principal.AWS` equal to or containing `"*"`. This rule flags managed policy resources where any statement authorizes `"*"` as a principal. Replace wildcards with explicit principals such as AWS account IDs, ARNs, or specific service principals to limit trust to known entities.

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
        Action: "logs:CreateLogGroup"
        Resource: "*"
        Principal:
          Service: "ec2.amazonaws.com"
          AWS: "*"
    make_default: false
    state: present

```