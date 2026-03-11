---
title: "Authentication Without MFA"
group_id: "Ansible / AWS"
meta:
  name: "aws/authentication_without_mfa"
  id: "eee107f9-b3d8-45d3-b9c6-43b5a7263ce1"
  display_name: "Authentication Without MFA"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `eee107f9-b3d8-45d3-b9c6-43b5a7263ce1`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_mfa_device_info_module.html)

### Description

Assume-role operations should require multi-factor authentication (MFA) to provide a second authentication factor and reduce the risk that compromised credentials or automated workflows can silently assume privileged roles. In Ansible, tasks using the `community.aws.sts_assume_role` or `sts_assume_role` modules must define both `mfa_serial_number` (the IAM MFA device ARN or serial) and `mfa_token` (the one-time MFA code). Tasks missing either property or with those properties undefined will be flagged. Supply `mfa_token` securely at runtime (for example via Ansible Vault, environment variables, or an interactive prompt) and ensure `mfa_serial_number` references the correct MFA device ARN (e.g., `arn:aws:iam::123456789012:mfa/username`).

## Compliant Code Examples
```yaml
- name: Assume an existing role
  community.aws.sts_assume_role:
    mfa_serial_number: '{{ mfa_devices.mfa_devices[0].serial_number }}'
    mfa_token: weewew
    role_arn: arn:aws:iam::123456789012:role/someRole
    role_session_name: someRoleSession
  register: assumed_role

- name: Hello
  sts_assume_role:
    mfa_serial_number: '{{ mfa_devices.mfa_devices[0].serial_number }}'
    mfa_token: weewew
    role_arn: arn:aws:iam::123456789012:role/someRole
    role_session_name: someRoleSession
  register: assumed_role

```
## Non-Compliant Code Examples
```yaml
- name: Assume an existing role
  community.aws.sts_assume_role:
    mfa_serial_number: "{{ mfa_devices.mfa_devices[0].serial_number }}"
    role_arn: "arn:aws:iam::123456789012:role/someRole"
    role_session_name: "someRoleSession"
  register: assumed_role

- name: Hello
  sts_assume_role:
    role_arn: "arn:aws:iam::123456789012:role/someRole"
    role_session_name: "someRoleSession"
  register: assumed_role

```