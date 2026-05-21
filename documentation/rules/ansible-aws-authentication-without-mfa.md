---
title: "Authentication without MFA"
group_id: "Ansible / AWS"
meta:
  name: "aws/authentication_without_mfa"
  id: "ansible-aws-authentication-without-mfa"
  display_name: "Authentication without MFA"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-authentication-without-mfa{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/iam_mfa_device_info_module.html)

### Description

Assume-role operations should require multi-factor authentication (MFA) to provide a second authentication factor and reduce the risk that compromised credentials or automated workflows can silently assume privileged roles.

In Ansible, tasks using the `amazon.aws.sts_assume_role` or `sts_assume_role` modules must define both `mfa_serial_number` (the IAM MFA device ARN or serial) and `mfa_token` (the one-time MFA code). Tasks missing either property or with those properties undefined are flagged.

Supply `mfa_token` securely at runtime (for example via Ansible Vault, environment variables, or an interactive prompt) and ensure `mfa_serial_number` references the correct MFA device ARN (for example, `arn:aws:iam::123456789012:mfa/username`).

## Compliant Code Examples
```yaml
- name: Assume an existing role
  amazon.aws.sts_assume_role:
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
  amazon.aws.sts_assume_role:
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