---
title: "Stack retention disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/stack_retention_disabled"
  id: "17d5ba1d-7667-4729-b1a6-b11fde3db7f7"
  display_name: "Stack retention disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** {{</* copyable-code */>}}17d5ba1d-7667-4729-b1a6-b11fde3db7f7{{</* copyable-code */>}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/cloudformation_stack_set_module.html#parameter-purge_stacks)

### Description

CloudFormation StackSet deletions must not purge stacks and their associated resources. Purging can irreversibly delete resources, causing data loss or service interruption. For Ansible tasks using the `community.aws.cloudformation_stack_set` module, the `purge_stacks` property must be explicitly set to the boolean value `false`. Resources missing `purge_stacks` or with `purge_stacks: true` are flagged.

```yaml
- name: Create or update StackSet without purging stacks on deletion
  community.aws.cloudformation_stack_set:
    name: my-stack-set
    template: /path/to/template.yaml
    parameters:
      Param1: value
    purge_stacks: false
```

## Compliant Code Examples
```yaml
- name: Create a stack set with instances in two accounts
  community.aws.cloudformation_stack_set:
    name: my-stack
    description: Test stack in two accounts
    state: present
    template_url: https://s3.amazonaws.com/my-bucket/cloudformation.template
    accounts: [1234567890, 2345678901]
    regions:
    - us-east-1
    purge_stacks: false

```
## Non-Compliant Code Examples
```yaml
- name: Create a stack set with instances in two accounts
  community.aws.cloudformation_stack_set:
    name: my-stack2
    description: Test stack in two accounts
    state: present
    template_url: https://s3.amazonaws.com/my-bucket/cloudformation.template
    accounts: [1234567890, 2345678901]
    regions:
    - us-east-1

- name: on subsequent calls, templates are optional but parameters and tags can be altered
  community.aws.cloudformation_stack_set:
    name: my-stack3
    state: present
    parameters:
      InstanceName: my_stacked_instance
    tags:
      foo: bar
      test: stack
    accounts: [1234567890, 2345678901]
    regions:
    - us-east-1
    purge_stacks: true

```