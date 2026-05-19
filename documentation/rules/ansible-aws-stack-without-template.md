---
title: "Stack without template"
group_id: "Ansible / AWS"
meta:
  name: "aws/stack_without_template"
  id: "ansible-aws-stack-without-template"
  display_name: "Stack without template"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-stack-without-template{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudformation_module.html)

### Description

CloudFormation stack tasks must specify exactly one template source. Missing or ambiguous templates can cause failed deployments or unintended resource changes that increase security and availability risks.

For Ansible modules `amazon.aws.cloudformation`, `cloudformation`, `community.aws.cloudformation_stack_set`, and `cloudformation_stack_set`, one of the properties `template`, `template_body`, or `template_url` must be present and non-empty. Resources that omit all three properties are flagged as missing a template. Resources that set more than one are flagged because multiple template sources are ambiguous and can lead to unexpected template selection.

Secure examples (valid configurations):

```yaml
- name: Create CloudFormation stack from local template
  amazon.aws.cloudformation:
    stack_name: my-stack
    template: /path/to/template.yaml

- name: Create CloudFormation stack from S3 URL
  amazon.aws.cloudformation:
    stack_name: my-stack
    template_url: https://s3.amazonaws.com/bucket/my-template.yaml
```

## Compliant Code Examples
```yaml
- name: create a stack, pass in the template body via lookup template v3
  amazon.aws.cloudformation:
    stack_name: ansible-cloudformation
    state: present
    region: us-east-1
    disable_rollback: true
    template_body: "{{ lookup('template', 'cloudformation.j2') }}"
    template_parameters:
      KeyName: jmartin
      DiskType: ephemeral
      InstanceType: m1.small
      ClusterSize: 3
    tags:
      Stack: ansible-cloudformation


- name: create a stack, pass in the template via an URL v4
  amazon.aws.cloudformation:
    stack_name: ansible-cloudformation
    state: present
    region: us-east-1
    disable_rollback: true
    template_url: https://s3.amazonaws.com/my-bucket/cloudformation.template
    template_parameters:
      KeyName: jmartin
      DiskType: ephemeral
      InstanceType: m1.small
      ClusterSize: 3
    tags:
      Stack: ansible-cloudformation


- name: Create a stack set with instances in two accounts  v5
  community.aws.cloudformation_stack_set:
    name: my-stack
    description: Test stack in two accounts
    state: present
    template_url: https://s3.amazonaws.com/my-bucket/cloudformation.template
    accounts: [1234567890, 2345678901]
    regions:
    - us-east-1

```
## Non-Compliant Code Examples
```yaml
- name: create a stack, pass in the template via an URL
  amazon.aws.cloudformation:
    stack_name: "ansible-cloudformation"
    state: present
    region: us-east-1
    disable_rollback: true
    template_parameters:
      KeyName: jmartin
      DiskType: ephemeral
      InstanceType: m1.small
      ClusterSize: 3
    tags:
      Stack: ansible-cloudformation
- name: create a stack, pass in the template via an URL v2
  amazon.aws.cloudformation:
    stack_name: "ansible-cloudformation"
    state: present
    region: us-east-1
    disable_rollback: true
    template_url: https://s3.amazonaws.com/my-bucket/cloudformation.template
    template_body: "{{ lookup('template', 'cloudformation.j2') }}"
    template_parameters:
      KeyName: jmartin
      DiskType: ephemeral
      InstanceType: m1.small
      ClusterSize: 3
    tags:
      Stack: ansible-cloudformation
- name: Create a stack set with instances in two accounts
  community.aws.cloudformation_stack_set:
    name: my-stack
    description: Test stack in two accounts
    state: present
    template_url: https://s3.amazonaws.com/my-bucket/cloudformation.template
    template_body: "{{ lookup('template', 'cloudformation.j2') }}"
    accounts: [1234567890, 2345678901]
    regions:
    - us-east-1
- name: Create a stack set with instances in two accounts v2
  community.aws.cloudformation_stack_set:
    name: my-stack
    description: Test stack in two accounts
    state: present
    accounts: [1234567890, 2345678901]
    regions:
    - us-east-1

```