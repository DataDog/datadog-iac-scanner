---
title: "No stack policy"
group_id: "Ansible / AWS"
meta:
  name: "aws/no_stack_policy"
  id: "ansible-aws-no-stack-policy"
  display_name: "No stack policy"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-no-stack-policy{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudformation_module.html)

### Description

CloudFormation stacks should have a stack policy to prevent unintended or unauthorized updates to stack resources, protecting critical resources from accidental changes or deployment mistakes.

For Ansible tasks using the `amazon.aws.cloudformation` or `cloudformation` modules, the `stack_policy` property must be defined and set to a valid JSON policy that restricts update actions. Resources missing the `stack_policy` property or with it undefined are flagged. Provide a JSON policy string (or file content) that explicitly denies Update actions for any logical resource IDs you want to protect.

Secure configuration example:

```yaml
- name: Create CloudFormation stack with stack policy
  amazon.aws.cloudformation:
    stack_name: my-stack
    state: present
    template: "{{ lookup('file', 'template.yml') }}"
    stack_policy: |
      {
        "Statement": [
          {
            "Effect": "Deny",
            "Action": "Update:*",
            "Principal": "*",
            "Resource": "LogicalResourceId/MyCriticalResource"
          }
        ]
      }
```

## Compliant Code Examples
```yaml
- name: create a stack, pass in the template via an URL
  amazon.aws.cloudformation:
    stack_name: ansible-cloudformation
    stack_policy: wowowowoowow
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

```
## Non-Compliant Code Examples
```yaml
- name: create a stack, pass in the template via an URL
  amazon.aws.cloudformation:
    stack_name: "ansible-cloudformation"
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

```