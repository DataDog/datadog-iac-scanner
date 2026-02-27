---
title: "Lambda permission principal is a wildcard"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/lambda_permission_principal_is_wildcard"
  id: "1d6e16f1-5d8a-4379-bfb3-2dadd38ed5a7"
  display_name: "Lambda permission principal is a wildcard"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `1d6e16f1-5d8a-4379-bfb3-2dadd38ed5a7`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html)

### Description

Granting a wildcard principal (`*`) in a Lambda permission makes the function publicly invokable, allowing any AWS account or unauthenticated caller to invoke it and potentially leading to unauthorized invocation, data exposure, or abuse. The `AWS::Lambda::Permission` resource's `Principal` property must specify an explicit principal, such as a service principal (for example, `sns.amazonaws.com`), an AWS account ARN, or a specific IAM principal. It must not be `*` or contain wildcard values. This rule flags `AWS::Lambda::Permission` resources where `Properties.Principal` contains `*`. To fix, set `Principal` to the intended principal and, when applicable, add `SourceArn` or other conditions to restrict which resources can invoke the function.

Secure configuration example:

```yaml
MyLambdaPermission:
  Type: AWS::Lambda::Permission
  Properties:
    FunctionName: !GetAtt MyFunction.Arn
    Action: lambda:InvokeFunction
    Principal: sns.amazonaws.com
    SourceArn: arn:aws:sns:us-east-1:123456789012:MyTopic
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster
Resources:
  s3Permission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !GetAtt function.Arn
      Action: lambda:InvokeFunction
      Principal: s3.amazonaws.com
      SourceAccount: !Ref 'AWS::AccountId'
      SourceArn: !GetAtt bucket.Arn

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster",
  "Resources": {
    "s3Permission": {
      "Type": "AWS::Lambda::Permission",
      "Properties": {
        "FunctionName": "function.Arn",
        "Action": "lambda:InvokeFunction",
        "Principal": "s3.amazonaws.com",
        "SourceAccount": "AWS::AccountId",
        "SourceArn": "bucket.Arn"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "s3Permission": {
      "Type": "AWS::Lambda::Permission",
      "Properties": {
        "SourceAccount": "AWS::AccountId",
        "SourceArn": "bucket.Arn",
        "FunctionName": "function.Arn",
        "Action": "lambda:InvokeFunction",
        "Principal": "*"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Creates RDS Cluster"
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: Creates RDS Cluster
Resources:
  s3Permission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !GetAtt function.Arn
      Action: lambda:InvokeFunction
      Principal: '*'
      SourceAccount: !Ref 'AWS::AccountId'
      SourceArn: !GetAtt bucket.Arn

```