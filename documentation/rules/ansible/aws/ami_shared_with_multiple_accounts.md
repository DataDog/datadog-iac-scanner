---
title: "AMI Shared With Multiple Accounts"
group_id: "Ansible / AWS"
meta:
  name: "aws/ami_shared_with_multiple_accounts"
  id: "a19b2942-142e-4e2b-93b7-6cf6a6c8d90f"
  display_name: "AMI Shared With Multiple Accounts"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `a19b2942-142e-4e2b-93b7-6cf6a6c8d90f`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/ec2_ami_module.html)

### Description

AMIs must not be broadly shared because granting multiple AWS accounts or group-based access increases the attack surface and can expose embedded credentials, custom configurations, or vulnerable images to unintended parties. For Ansible tasks using the `amazon.aws.ec2_ami` or `ec2_ami` modules, the `launch_permissions` property should be restricted to at most one explicit AWS account and must not include `group_names`. This rule flags tasks where `launch_permissions.group_names` is present (any group sharing) or where `launch_permissions.user_ids` contains more than one entry. Secure example with a single allowed account:

```yaml
- name: Register AMI with restricted launch permissions
  amazon.aws.ec2_ami:
    name: my-ami
    image_id: ami-0123456789abcdef0
    launch_permissions:
      user_ids:
        - "123456789012"
```

## Compliant Code Examples
```yaml
- name: Allow AMI to be launched by another account V2
  amazon.aws.ec2_ami:
    image_id: '{{ instance.image_id }}'
    state: present
    launch_permissions:
      user_ids: ['123456789012']

```
## Non-Compliant Code Examples
```yaml
- name: Update AMI Launch Permissions, making it public
  amazon.aws.ec2_ami:
    image_id: "{{ instance.image_id }}"
    state: present
    launch_permissions:
      group_names: ['all']
- name: Allow AMI to be launched by another account
  amazon.aws.ec2_ami:
    image_id: "{{ instance.image_id }}"
    state: present
    launch_permissions:
      user_ids: ['123456789012', '121212']

```