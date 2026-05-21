---
title: "Lambda permission misconfigured"
group_id: "Ansible / AWS"
meta:
  name: "aws/lambda_permission_misconfigured"
  id: "ansible-aws-lambda-permission-misconfigured"
  display_name: "Lambda permission misconfigured"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}ansible-aws-lambda-permission-misconfigured{{< /copyable-code >}}

**Provider:** AWS

**Platform:** Ansible

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/lambda_policy_module.html)

### Description

Lambda permission statements must set the action to `lambda:InvokeFunction` so callers are limited to invoking the function and cannot receive broader or unintended Lambda privileges.

Check Ansible tasks that use the `amazon.aws.lambda_policy` or `lambda_policy` modules. The `action` property must be defined and set to the exact string `lambda:InvokeFunction`. Tasks missing the `action` property or using any other value (for example `lambda:*`, a different Lambda action, or an empty value) are flagged because they can over-privilege callers or result in misconfigured access.

Secure example with the action explicitly set:

```yaml
- name: Allow S3 to invoke my Lambda
  amazon.aws.lambda_policy:
    name: my_lambda_policy
    state: present
    principal: s3.amazonaws.com
    action: lambda:InvokeFunction
    function_name: my-function
```

## Compliant Code Examples
```yaml
- name: Lambda S3 notification negative
  amazon.aws.lambda_policy:
    state: present
    function_name: functionName
    alias: Dev
    statement_id: lambda-s3-myBucket-create-data-log
    action: lambda:InvokeFunction
    principal: s3.amazonaws.com
    source_arn: arn:aws:s3:eu-central-1:123456789012:bucketName
    source_account: 123456789012

```
## Non-Compliant Code Examples
```yaml
- name: Lambda S3 notification positive
  amazon.aws.lambda_policy:
    state: present
    function_name: functionName
    alias: Dev
    statement_id: lambda-s3-myBucket-create-data-log
    action: lambda:CreateFunction
    principal: s3.amazonaws.com
    source_arn: arn:aws:s3:eu-central-1:123456789012:bucketName
    source_account: 123456789012

```