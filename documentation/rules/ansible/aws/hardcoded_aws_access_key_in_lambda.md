---
title: "Hardcoded AWS access key in Lambda"
group_id: "Ansible / AWS"
meta:
  name: "aws/hardcoded_aws_access_key_in_lambda"
  id: "f34508b9-f574-4330-b42d-88c44cced645"
  display_name: "Hardcoded AWS access key in Lambda"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `f34508b9-f574-4330-b42d-88c44cced645`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/lambda_module.html)

### Description

Hardcoding AWS secret access keys in Ansible Lambda tasks exposes credentials to source control, logs, and build artifacts. Attackers who obtain the key can impersonate the account and access AWS resources. This check targets Ansible tasks using the `amazon.aws.lambda` or `lambda` modules and flags tasks that include an `aws_access_key` property containing a 40-character plaintext secret (matched by regex `^[A-Za-z0-9/+=]{40}$`).

Do not set `aws_access_key` or `aws_secret_key` inline. Instead, supply credentials via IAM instance/profile roles, shared AWS credential profiles, environment variables, or encrypted secrets (Ansible Vault or a secrets manager). You can also reference vaulted or lookup variables in the task. Tasks with a literal 40-character `aws_access_key` value are flagged. Omitting the properties to rely on role-based auth or referencing vaulted variables is acceptable.

Secure examples:

```yaml
- name: Deploy Lambda using instance profile (no inline credentials)
  amazon.aws.lambda:
    name: my_function
    state: present
    region: us-east-1
```

```yaml
- name: Deploy Lambda with credentials stored in Ansible Vault
  amazon.aws.lambda:
    name: my_function
    state: present
    region: us-east-1
    aws_access_key: "{{ vault_aws_access_key }}"
    aws_secret_key: "{{ vault_aws_secret_key }}"
```

## Compliant Code Examples
```yaml
- name: looped creation
  amazon.aws.lambda:
    name: '{{ item.name }}'
    state: present
    zip_file: '{{ item.zip_file }}'
    runtime: python2.7
    role: arn:aws:iam::987654321012:role/lambda_basic_execution
    handler: hello_python.my_handler
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
- name: remove tags
  amazon.aws.lambda:
    name: Lambda function
    state: present
    zip_file: code.zip
    runtime: python2.7
    role: arn:aws:iam::987654321012:role/lambda_basic_execution
    handler: hello_python.my_handler
    tags: {}
- name: Delete Lambda functions HelloWorld and ByeBye
  amazon.aws.lambda:
    name: '{{ item }}'
    state: absent
    loop:
      - HelloWorld
      - ByeBye

```
## Non-Compliant Code Examples
```yaml
- name: looped creation
  amazon.aws.lambda:
    aws_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
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
- name: remove tags
  amazon.aws.lambda:
    aws_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    name: 'Lambda function'
    state: present
    zip_file: code.zip
    runtime: 'python2.7'
    role: 'arn:aws:iam::987654321012:role/lambda_basic_execution'
    handler: 'hello_python.my_handler'
    tags: {}
- name: Delete Lambda functions HelloWorld and ByeBye
  amazon.aws.lambda:
    name: '{{ item }}'
    state: absent
    loop:
      - HelloWorld
      - ByeBye

```