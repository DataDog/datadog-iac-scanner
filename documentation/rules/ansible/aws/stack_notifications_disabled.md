---
title: "Stack notifications disabled"
group_id: "Ansible / AWS"
meta:
  name: "aws/stack_notifications_disabled"
  id: "d39761d7-94ab-45b0-ab5e-27c44e381d58"
  display_name: "Stack notifications disabled"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}d39761d7-94ab-45b0-ab5e-27c44e381d58{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/cloudformation_module.html#parameter-notification_arns)

### Description

CloudFormation stacks should publish notifications so operators are alerted to important stack events, such as failed deployments or unexpected stack changes. Without notifications, security incidents or configuration drift can go undetected and response times increase. In Ansible, tasks using the `amazon.aws.cloudformation` or legacy `cloudformation` module must define the `notification_arns` parameter and set it to one or more SNS topic ARNs. Resources missing `notification_arns` are flagged for remediation.

Secure example:

```yaml
- name: Create or update CloudFormation stack with notifications
  amazon.aws.cloudformation:
    stack_name: my-stack
    state: present
    template_body: "{{ lookup('file', 'template.yaml') }}"
    notification_arns:
      - arn:aws:sns:us-east-1:123456789012:stack-notifications
```

## Compliant Code Examples
```yaml
- name: create a stack, pass in the template via an URL
  amazon.aws.cloudformation:
    stack_name: ansible-cloudformation
    stack_policy: wowowowoowow
    notification_arns: a, b
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