---
title: "Lambda permission principal is wildcard"
group_id: "Ansible / AWS"
meta:
  name: "aws/lambda_permission_principal_is_wildcard"
  id: "1d972c56-8ec2-48c1-a578-887adb09c57a"
  display_name: "Lambda permission principal is wildcard"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}1d972c56-8ec2-48c1-a578-887adb09c57a{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/lambda_policy_module.html)

### Description

Lambda function permissions must not use wildcard principals (`*`). This effectively allows any AWS account or anonymous principal to invoke the function, increasing the risk of unauthorized invocations and data exposure.

In Ansible, check tasks using the `amazon.aws.lambda_policy` or `lambda_policy` modules and ensure the `principal` property does not contain `*` or other wildcard values. The `principal` must specify explicit principals such as an AWS account ARN, role ARN, or service principal (for example, `arn:aws:iam::123456789012:role/MyRole` or `events.amazonaws.com`). Tasks where `principal` includes `*` are flagged.

Secure example using an explicit service principal:

```yaml
- name: Allow EventBridge to invoke Lambda
  amazon.aws.lambda_policy:
    state: present
    function_name: my-function
    principal: events.amazonaws.com
    action: lambda:InvokeFunction
    source_arn: arn:aws:events:us-east-1:123456789012:rule/MyRule
```

## Compliant Code Examples
```yaml
- name: Lambda S3 event notification negative
  amazon.aws.lambda_policy:
    state: present
    function_name: functionName
    alias: Dev
    statement_id: lambda-s3-myBucket-create-data-log
    action: lambda:AddPermission
    principal: s3.amazonaws.com
    source_arn: arn:aws:s3:eu-central-1:123456789012:bucketName
    source_account: 123456789012

```
## Non-Compliant Code Examples
```yaml
- name: Lambda S3 event notification
  amazon.aws.lambda_policy:
    state: present
    function_name: functionName
    alias: Dev
    statement_id: lambda-s3-myBucket-create-data-log
    action: lambda:AddPermission
    principal: "*"
    source_arn: arn:aws:s3:eu-central-1:123456789012:bucketName
    source_account: 123456789012

```