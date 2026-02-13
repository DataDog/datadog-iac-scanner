---
title: "Lambda function without dead-letter queue"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/lambda_function_without_dead_letter_queue"
  id: "c2eae442-d3ba-4cb1-84ca-1db4f80eae3d"
  display_name: "Lambda function without dead-letter queue"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `c2eae442-d3ba-4cb1-84ca-1db4f80eae3d`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html#cfn-lambda-function-deadletterconfig)

### Description

 Lambda functions should be configured with a dead-letter queue (DLQ) to capture failed asynchronous invocations and prevent message loss or silent failures. In AWS CloudFormation, `AWS::Lambda::Function` resources should define `Properties.DeadLetterConfig.TargetArn` and set it to a valid destination ARN (typically an Amazon SQS queue or Amazon SNS topic). Resources missing `DeadLetterConfig` or where `DeadLetterConfig.TargetArn` is undefined or `null` will be flagged.

Secure configuration example (CloudFormation YAML):

```yaml
MyDLQ:
  Type: AWS::SQS::Queue
  Properties:
    QueueName: my-dlq

MyFunction:
  Type: AWS::Lambda::Function
  Properties:
    FunctionName: my-function
    Runtime: nodejs14.x
    Handler: index.handler
    Role: arn:aws:iam::123456789012:role/lambda-role
    DeadLetterConfig:
      TargetArn: !GetAtt MyDLQ.Arn
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: VPC function.
Resources:
  Function3:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
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
      Tags:
        - Key: Description
          Value: VPC Function
        - Key: Type
          Value: AWS Lambda Function
      DeadLetterConfig:
        TargetArn: arn:aws:sqs:us-east-1:2324243535:aaa

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: VPC function.
Resources:
  Function2:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
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
      Tags:
        - Key: Description
          Value: VPC Function
        - Key: Type
          Value: AWS Lambda Function
      DeadLetterConfig:

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: VPC function.
Resources:
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: arn:aws:iam::123456789012:role/lambda-role
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
      Tags:
        - Key: Description
          Value: VPC Function
        - Key: Type
          Value: AWS Lambda Function

```