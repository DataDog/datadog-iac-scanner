---
title: "Lambda permission misconfigured"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/lambda_permission_misconfigured"
  id: "9b83114b-b2a1-4534-990d-06da015e47aa"
  display_name: "Lambda permission misconfigured"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `9b83114b-b2a1-4534-990d-06da015e47aa`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/pt_br/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html)

### Description

Lambda permissions must explicitly allow only the invocation action to enforce least privilege and prevent unintended access to other function operations or configuration. In AWS CloudFormation, the `Action` property in `AWS::Lambda::Permission` resources must be set exactly to `lambda:InvokeFunction`. Resources missing `Action` or with any other value will be flagged as a security risk. 
 
 Secure CloudFormation example:

```yaml
MyFunctionPermission:
  Type: AWS::Lambda::Permission
  Properties:
    FunctionName: !GetAtt MyFunction.Arn
    Action: lambda:InvokeFunction
    Principal: sns.amazonaws.com
```

## Compliant Code Examples
```yaml
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
        "SourceArn": "bucket.Arn",
        "FunctionName": "function.Arn",
        "Action": "lambda:GetFunction",
        "Principal": "s3.amazonaws.com",
        "SourceAccount": "AWS::AccountId"
      }
    }
  }
}

```

```yaml
Resources:
  s3Permission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !GetAtt function.Arn
      Action: lambda:GetFunction
      Principal: s3.amazonaws.com
      SourceAccount: !Ref 'AWS::AccountId'
      SourceArn: !GetAtt bucket.Arn

```