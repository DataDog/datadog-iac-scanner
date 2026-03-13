---
title: "IAM policies attached to user"
group_id: "Ansible / AWS"
meta:
  name: "aws/iam_policies_attached_to_user"
  id: "eafe4bc3-1042-4f88-b988-1939e64bf060"
  display_name: "IAM policies attached to user"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `eafe4bc3-1042-4f88-b988-1939e64bf060`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_policy_module.html)

### Description

Attaching IAM policies directly to individual IAM users increases the risk of privilege sprawl, makes permissions harder to audit and revoke, and magnifies impact if a user's credentials are compromised.

For Ansible `community.aws.iam_policy` or `iam_policy` tasks, the `iam_type` property must be set to `group` or `role` rather than `user`. Resources missing the `iam_type` property or with `iam_type` set to `user` are flagged. Attach policies to groups or roles to centralize permission management and enable role-based access patterns.

Secure example (attach policy to a role):

```yaml
- name: Attach policy to role
  community.aws.iam_policy:
    name: my-policy
    policy_document: "{{ lookup('file', 'my-policy.json') }}"
    iam_type: role
    iam_name: my-role
```

## Compliant Code Examples
```yaml
- name: Assign a policy called Admin to the administrators group
  community.aws.iam_policy:
    iam_type: group
    iam_name: administrators
    policy_name: Admin
    state: present
    policy_document: admin_policy.json

```
## Non-Compliant Code Examples
```yaml
- name: Assign a policy called Admin to user
  community.aws.iam_policy:
    iam_type: user
    iam_name: administrators
    policy_name: Admin
    state: present
    policy_document: admin_policy.json

```