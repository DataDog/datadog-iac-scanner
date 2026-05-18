---
title: "Lambda function without tags"
group_id: "Ansible / AWS"
meta:
  name: "aws/lambda_function_without_tags"
  id: "ansible-aws-lambda-function-without-tags"
  display_name: "Lambda function without tags"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-lambda-function-without-tags{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/lambda_module.html)

### Description

AWS Lambda functions should be tagged so resources can be reliably inventoried and assigned ownership. Tags also enable tag-based access controls and automated security or operational workflows.

In Ansible playbooks, tasks using the `amazon.aws.lambda` or legacy `lambda` module must define the `tags` property as a mapping/dictionary. Resources where `tags` is undefined are flagged. Ensure `tags` is present on the module invocation and contains at least the necessary keys for your organization (for example, `Owner`, `Environment`, or `Project`).

Secure example:

```yaml
- name: create application lambda
  amazon.aws.lambda:
    name: my-function
    state: present
    runtime: python3.9
    role: arn:aws:iam::123456789012:role/lambda-exec
    handler: app.handler
    tags:
      Owner: team-foo
      Environment: production
      Project: billing
```

## Compliant Code Examples
```yaml
- name: add tags
  amazon.aws.lambda:
    name: 'Lambda function'
    state: present
    zip_file: 'code.zip'
    runtime: 'python2.7'
    role: 'arn:aws:iam::987654321012:role/lambda_basic_execution'
    handler: 'hello_python.my_handler'
    tags:
      key1: 'value1'

```
## Non-Compliant Code Examples
```yaml
- name: add tags
  amazon.aws.lambda:
    name: 'Lambda function'
    state: present
    zip_file: 'code.zip'
    runtime: 'python2.7'
    role: 'arn:aws:iam::987654321012:role/lambda_basic_execution'
    handler: 'hello_python.my_handler'

```