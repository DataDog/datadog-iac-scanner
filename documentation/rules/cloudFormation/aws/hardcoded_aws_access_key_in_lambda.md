---
title: "Hardcoded AWS access key in Lambda"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/hardcoded_aws_access_key_in_lambda"
  id: "2564172f-c92b-4261-9acd-464aed511696"
  display_name: "Hardcoded AWS access key in Lambda"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `2564172f-c92b-4261-9acd-464aed511696`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-environment)

### Description

 Lambda functions must not include hardcoded AWS access keys or secret access keys in environment variables because embedded credentials can be exposed via function configuration, logs, snapshots, or code and allow unauthorized access to other AWS resources.
 
 This rule inspects `AWS::Lambda::Function` resources and verifies the `Properties.Environment.Variables` map does not contain values matching common AWS access key ID patterns (`20` uppercase alphanumeric characters) or secret access key patterns (`40` base64-like characters). Use IAM execution roles for permissions or store secrets in AWS Secrets Manager or AWS Systems Manager Parameter Store `SecureString` parameters and reference them from the function. Resources with environment variable values that match the access-key regex will be flagged. 
 
 Secure example using a Secrets Manager dynamic reference:

```yaml
MyFunction:
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: my-function
    Role: arn:aws:iam::123456789012:role/lambda-exec-role
    Handler: index.handler
    Runtime: nodejs14.x
    Environment:
      Variables:
        DB_PASSWORD: '{{resolve:secretsmanager:my-db-secret:SecretString:password}}'
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: VPC function.
Resources:
  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Environment:
        Variables:
          foo: "test"
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "VPC function.",
  "Resources": {
    "LambdaFunction2": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Code": {
          "S3Bucket": "my-bucket",
          "S3Key": "function.zip"
        },
        "Runtime": "nodejs12.x",
        "Timeout": 5,
        "TracingConfig": {
          "Mode": "Active"
        },
        "VpcConfig": {
          "SecurityGroupIds": [
            "sg-085912345678492fb"
          ],
          "SubnetIds": [
            "subnet-071f712345678e7c8",
            "subnet-07fd123456788a036"
          ]
        },
        "Handler": "index.handler",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Environment": {
          "Variables": {
            "foo": "test"
          }
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: VPC function.
Resources:
  LambdaFunction4:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
      Environment:
        Variables:
          foo: "12345678901234567890123456789012345678901234567890123456789012345678901234567890$"
      Code:
        S3Bucket: my-bucket
        S3Key: function.zip
      Runtime: nodejs12.x
      Timeout: 5
      TracingConfig:
        Mode: Active
      VpcConfig:
        SecurityGroupIds:
          - sg-085912345678492fb
        SubnetIds:
          - subnet-071f712345678e7c8
          - subnet-07fd123456788a036

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "VPC function.",
  "Resources": {
    "LambdaFunction5": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Code": {
          "S3Bucket": "my-bucket",
          "S3Key": "function.zip"
        },
        "Runtime": "nodejs12.x",
        "Timeout": 5,
        "TracingConfig": {
          "Mode": "Active"
        },
        "VpcConfig": {
          "SecurityGroupIds": [
            "sg-085912345678492fb"
          ],
          "SubnetIds": [
            "subnet-071f712345678e7c8",
            "subnet-07fd123456788a036"
          ]
        },
        "Handler": "index.handler",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Environment": {
          "Variables": {
            "foo": "1234567890123456789012345678901234567890$",
            "databaseName": "lambdadb",
            "databaseUser": "admin"
          }
        }
      }
    }
  }
}

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "VPC function.",
  "Resources": {
    "LambdaFunction6": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Code": {
          "S3Bucket": "my-bucket",
          "S3Key": "function.zip"
        },
        "Runtime": "nodejs12.x",
        "Timeout": 5,
        "TracingConfig": {
          "Mode": "Active"
        },
        "VpcConfig": {
          "SecurityGroupIds": [
            "sg-085912345678492fb"
          ],
          "SubnetIds": [
            "subnet-071f712345678e7c8",
            "subnet-07fd123456788a036"
          ]
        },
        "Handler": "index.handler",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Environment": {
          "Variables": {
            "foo": "12345678901234567890123456789012345678901234567890123456789012345678901234567890$"
          }
        }
      }
    }
  }
}

```