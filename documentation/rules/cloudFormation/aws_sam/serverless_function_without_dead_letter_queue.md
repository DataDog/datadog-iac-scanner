---
title: "Serverless function without dead-letter queue"
group_id: "CloudFormation / AWS"
meta:
  name: "aws_sam/serverless_function_without_dead_letter_queue"
  id: "cb2f612b-ed42-4ff5-9fb9-255c73d39a18"
  display_name: "Serverless function without dead-letter queue"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `cb2f612b-ed42-4ff5-9fb9-255c73d39a18`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-deadletterqueue)

### Description

 Serverless functions without a dead-letter queue (DLQ) can lose events from failed asynchronous invocations and make failure diagnosis and recovery difficult. For `AWS::Serverless::Function` resources, the `DeadLetterConfig` property must be defined and not `null`. The `DeadLetterConfig` should include a valid `TargetArn` that points to a durable target such as an Amazon SQS queue or an Amazon SNS topic; resources missing `DeadLetterConfig` or with it set to `null` will be flagged.

Secure configuration example:

```yaml
MyDeadLetterQueue:
  Type: AWS::SQS::Queue

MyFunction:
  Type: AWS::Serverless::Function
  Properties:
    Handler: index.handler
    Runtime: nodejs14.x
    DeadLetterConfig:
      TargetArn: !GetAtt MyDeadLetterQueue.Arn
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  Function1:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
      Tags:
        - Key: Type
          Value: AWS Serverless Function
      DeadLetterConfig:
        TargetArn: arn:aws:sqs:us-east-1:2324243535:aaa
        Type: SQS

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  Function:
    Type: AWS::Serverless::Function
    Properties:
      PackageType: Image
      ImageUri: account-id.dkr.ecr.region.amazonaws.com/ecr-repo-name:image-name
      ImageConfig:
        Command:
          - "app.lambda_handler"
        EntryPoint:
          - "entrypoint1"
        WorkingDirectory: "workDir"
      Tags:
        - Key: Type
          Value: AWS Serverless Function

```