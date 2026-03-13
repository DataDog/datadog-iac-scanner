---
title: "Public Lambda via API Gateway"
group_id: "Ansible / AWS"
meta:
  name: "aws/public_lambda_via_api_gateway"
  id: "5e92d816-2177-4083-85b4-f61b4f7176d9"
  display_name: "Public Lambda via API Gateway"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `5e92d816-2177-4083-85b4-f61b4f7176d9`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/2.4/lambda_policy_module.html)

### Description

Allowing API Gateway to invoke a Lambda using a wildcard source ARN like `/*/*` grants any API, stage, or method the ability to invoke the function. This can result in unintended public or cross-account invocation and increase the risk of unauthorized execution.

In Ansible tasks using the `community.aws.lambda_policy` or `lambda_policy` modules, the `source_arn` property must not be set to `/*/*`. Instead, specify the full execute-api ARN (for example `arn:aws:execute-api:<region>:<account-id>:<api-id>/<stage>/<HTTP-VERB>/<resource>`).

This rule flags policies where `action` is `lambda:InvokeFunction` or `lambda:*` and `principal` is `apigateway.amazonaws.com` or `*` while `source_arn` matches `/*/*`. Avoid using a wildcard principal and prefer the explicit `apigateway.amazonaws.com` principal with a narrowed `source_arn`. 

Secure configuration example:

```yaml
- name: Allow specific API Gateway to invoke Lambda
  community.aws.lambda_policy:
    function_name: my-function
    action: lambda:InvokeFunction
    principal: apigateway.amazonaws.com
    source_arn: arn:aws:execute-api:us-east-1:123456789012:abcd1234/prod/POST/myresource
```

## Compliant Code Examples
```yaml
- name: Lambda S3 event notification
  lambda_policy:
    state: "{{ state | default('present') }}"
    function_name: functionName
    alias: Dev
    statement_id: lambda-s3-myBucket-create-data-log
    action: lambda:InvokeFunction
    principal: s3.amazonaws.com
    source_arn: arn:aws:s3:eu-central-1:123456789012:bucketname

```
## Non-Compliant Code Examples
```yaml
- name: Lambda S3 event notification
  lambda_policy:
    state: "{{ state | default('present') }}"
    function_name: functionName
    alias: Dev
    statement_id: lambda-s3-myBucket-create-data-log
    action: lambda:InvokeFunction
    principal: apigateway.amazonaws.com
    source_arn: arn:aws:s3:eu-central-1:123456789012/*/*

```