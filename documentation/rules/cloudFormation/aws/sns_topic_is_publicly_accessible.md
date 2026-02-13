---
title: "SNS topic is publicly accessible"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/sns_topic_is_publicly_accessible"
  id: "ae53ce91-42b5-46bf-a84f-9a13366a4f13"
  display_name: "SNS topic is publicly accessible"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `ae53ce91-42b5-46bf-a84f-9a13366a4f13`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html)

### Description

 SNS topic policies must not grant `Allow` permissions to all principals because that effectively makes the topic public. This can allow unauthenticated users or arbitrary AWS accounts to publish to or subscribe from the topic, risking data exposure, spam, and abuse.

Check `AWS::SNS::TopicPolicy` resources' `Properties.PolicyDocument.Statement` entries. Any statement with `Effect: "Allow"` and `Principal: "*"`, or `Principal.AWS: "*"`, will be flagged.

To remediate, require explicit principals such as AWS account ARNs or service principals, or use scoped conditions for cross-account access rather than wildcard principals. Statements that list wildcard principals, or omit principal restrictions, should be corrected.

Secure configuration example (CloudFormation YAML):

```yaml
MyTopicPolicy:
  Type: AWS::SNS::TopicPolicy
  Properties:
    Topics:
      - !Ref MyTopic
    PolicyDocument:
      Version: '2012-10-17'
      Statement:
        - Effect: Allow
          Principal:
            AWS: arn:aws:iam::123456789012:root
          Action:
            - sns:Publish
          Resource: !Ref MyTopic
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: ''
Resources:
  snsPolicy:
      Type: AWS::SNS::TopicPolicy
      Properties:
        PolicyDocument:
          Statement: [
            {
              "Sid": "MyTopicPolicy",
              "Effect": "Allow",
              "Principal": "otherPrincipal",
              "Action": ["sns:Publish"],
              "Resource": "arn:aws:sns:MyTopic"
            }]

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "",
  "Resources": {
    "mysnspolicy0" : {
      "Type" : "AWS::SNS::TopicPolicy",
      "Properties" : {
        "PolicyDocument" :  {
          "Id" : "MyTopicPolicy",
          "Version" : "2012-10-17",
          "Statement" : [ {
            "Sid" : "My-statement-id",
            "Effect" : "Allow",
            "Principal" : "otherPrincipal",
            "Action" : "sns:Publish",
            "Resource" : "*"
          } ]
        },
        "Topics" : [ { "Ref" : "MySNSTopic" } ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "",
  "Resources": {
    "mysnspolicy0" : {
      "Type" : "AWS::SNS::TopicPolicy",
      "Properties" : {
        "PolicyDocument" :  {
          "Id" : "MyTopicPolicy",
          "Version" : "2012-10-17",
          "Statement" : [ {
            "Sid" : "My-statement-id",
            "Effect" : "Allow",
            "Principal" : "*",
            "Action" : "sns:Publish",
            "Resource" : "*"
          } ]
        },
        "Topics" : [ { "Ref" : "MySNSTopic" } ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: ''
Resources:
  snsPolicy:
      Type: AWS::SNS::TopicPolicy
      Properties:
        PolicyDocument:
          Statement: [
            {
              "Sid": "MyTopicPolicy",
              "Effect": "Allow",
              "Principal": "*",
              "Action": ["sns:Publish"],
              "Resource": "arn:aws:sns:MyTopic"
            }]

```