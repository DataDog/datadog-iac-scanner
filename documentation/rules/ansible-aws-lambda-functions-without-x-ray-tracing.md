---
title: "Lambda functions without X-Ray tracing"
group_id: "Ansible / AWS"
meta:
  name: ""aws/lambda_functions_without_x-ray_tracing""
  id: "ansible-aws-lambda-functions-without-x-ray-tracing"
  display_name: "Lambda functions without X-Ray tracing"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-lambda-functions-without-x-ray-tracing{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/lambda_module.html)

### Description

Lambda functions should have active AWS X-Ray tracing enabled to provide end-to-end request visibility and help detect performance problems and security incidents. For Ansible `amazon.aws.lambda` or `lambda` module tasks, the `tracing_mode` property must be defined and set to `Active`. Tasks that omit `tracing_mode` or set it to any value other than `Active` are flagged.

Secure Ansible example:

```yaml
- name: Create Lambda with active X-Ray tracing
  amazon.aws.lambda:
    name: my_lambda_function
    state: present
    runtime: python3.9
    handler: app.handler
    tracing_mode: Active
```

## Compliant Code Examples
```yaml
- name: looped creation V3
  amazon.aws.lambda:
    name: '{{ item.name }}'
    state: present
    zip_file: '{{ item.zip_file }}'
    runtime: python2.7
    role: arn:aws:iam::987654321012:role/lambda_basic_execution
    handler: hello_python.my_handler
    tracing_mode: Active
    vpc_subnet_ids:
    - subnet-123abcde
    - subnet-edcba321
    vpc_security_group_ids:
    - sg-123abcde
    - sg-edcba321
    environment_variables: '{{ item.env_vars }}'
    tags:
      key1: value1
  loop:
  - name: HelloWorld
    zip_file: hello-code.zip
    env_vars:
      key1: first
      key2: second
  - name: ByeBye
    zip_file: bye-code.zip
    env_vars:
      key1: '1'
      key2: '2'

```
## Non-Compliant Code Examples
```yaml
- name: looped creation
  amazon.aws.lambda:
    name: '{{ item.name }}'
    state: present
    zip_file: '{{ item.zip_file }}'
    runtime: 'python2.7'
    role: 'arn:aws:iam::987654321012:role/lambda_basic_execution'
    handler: 'hello_python.my_handler'
    vpc_subnet_ids:
    - subnet-123abcde
    - subnet-edcba321
    vpc_security_group_ids:
    - sg-123abcde
    - sg-edcba321
    environment_variables: '{{ item.env_vars }}'
    tags:
      key1: 'value1'
  loop:
  - name: HelloWorld
    zip_file: hello-code.zip
    env_vars:
      key1: "first"
      key2: "second"
  - name: ByeBye
    zip_file: bye-code.zip
    env_vars:
      key1: "1"
      key2: "2"
- name: looped creation V2
  amazon.aws.lambda:
    name: '{{ item.name }}'
    state: present
    zip_file: '{{ item.zip_file }}'
    runtime: 'python2.7'
    role: 'arn:aws:iam::987654321012:role/lambda_basic_execution'
    handler: 'hello_python.my_handler'
    tracing_mode: "PassThrough"
    vpc_subnet_ids:
    - subnet-123abcde
    - subnet-edcba321
    vpc_security_group_ids:
    - sg-123abcde
    - sg-edcba321
    environment_variables: '{{ item.env_vars }}'
    tags:
      key1: 'value1'
  loop:
  - name: HelloWorld
    zip_file: hello-code.zip
    env_vars:
      key1: "first"
      key2: "second"
  - name: ByeBye
    zip_file: bye-code.zip
    env_vars:
      key1: "1"
      key2: "2"

```