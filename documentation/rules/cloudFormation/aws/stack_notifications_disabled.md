---
title: "Stack notifications disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/stack_notifications_disabled"
  id: "837e033c-4717-40bd-807e-6abaa30161b7"
  display_name: "Stack notifications disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `837e033c-4717-40bd-807e-6abaa30161b7`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-stack.html)

### Description

CloudFormation stacks should send notifications for stack events so operators are promptly alerted to failed or unexpected stack creations, updates, or deletions.

For `AWS::CloudFormation::Stack` resources, `Properties.NotificationARNs` must be defined and set to a list of SNS topic ARNs (or CloudFormation references to `AWS::SNS::Topic` resources) so events are forwarded to your alerting channels. Resources missing `NotificationARNs`, or configured with an empty list, will be flagged because lack of notifications delays detection of provisioning failures and security-relevant changes.

Configure `NotificationARNs` with explicit ARNs or `Ref`/`GetAtt` to SNS topics to ensure reliable delivery. For example:

```yaml
NotificationTopic:
  Type: AWS::SNS::Topic

MyStack:
  Type: AWS::CloudFormation::Stack
  Properties:
    TemplateURL: https://s3.amazonaws.com/example/template.yml
    NotificationARNs:
      - !Ref NotificationTopic
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myStackWithParams:
    Type: AWS::CloudFormation::Stack
    Properties:
      NotificationARNs:
        - "String"
      TemplateURL: https://s3.amazonaws.com/cloudformation-templates-us-east-2/EC2ChooseAMI.template
      Parameters:
        InstanceType: t1.micro
        KeyName: mykey

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myStackWithParams": {
      "Type": "AWS::CloudFormation::Stack",
      "Properties": {
        "NotificationARNs": [
          "string"
        ],
        "TemplateURL": "https://s3.amazonaws.com/cloudformation-templates-us-east-2/EC2ChooseAMI.template",
        "Parameters": {
          "InstanceType": "t1.micro",
          "KeyName": "mykey"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myStackWithParams": {
      "Type": "AWS::CloudFormation::Stack",
      "Properties": {
        "TemplateURL": "https://s3.amazonaws.com/cloudformation-templates-us-east-2/EC2ChooseAMI.template",
        "Parameters": {
          "InstanceType": "t1.micro",
          "KeyName": "mykey"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  myStackWithParams:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: https://s3.amazonaws.com/cloudformation-templates-us-east-2/EC2ChooseAMI.template
      Parameters:
        InstanceType: t1.micro
        KeyName: mykey

```