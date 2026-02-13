---
title: "CloudTrail SNS topic name undefined"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudtrail_sns_topic_name_undefined"
  id: "3e09413f-471e-40f3-8626-990c79ae63f3"
  display_name: "CloudTrail SNS topic name undefined"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `3e09413f-471e-40f3-8626-990c79ae63f3`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-snstopicname)

### Description

 CloudTrail trails should be configured to publish notifications to an Amazon SNS topic so that security teams receive real-time alerts for suspicious events and automated workflows can be triggered for faster detection and response.

 This rule checks `AWS::CloudTrail::Trail` resources to ensure the `SnsTopicName` property is defined and non-empty. Resources missing `SnsTopicName` or with `SnsTopicName` set to `""` will be flagged. Ensure the property references a valid Amazon SNS topic that allows CloudTrail to publish. 
 
 Secure example (CloudFormation YAML):

```yaml
AuditTopic:
  Type: AWS::SNS::Topic

MyTrail:
  Type: AWS::CloudTrail::Trail
  Properties:
    S3BucketName: my-audit-bucket
    IsLogging: true
    SnsTopicName: !Ref AuditTopic
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  OperatorEmail:
    Description: "Email address to notify when new logs are published."
    Type: String
Resources:
  myTrail:
    DependsOn:
      - BucketPolicy
      - TopicPolicy
    Type: AWS::CloudTrail::Trail
    Properties:
      EnableLogFileValidation: true
      S3BucketName:
        Ref: S3Bucket
      SnsTopicName:
        Fn::GetAtt:
          - Topic
          - TopicName
      IsLogging: true
      IsMultiRegionTrail: true

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "OperatorEmail": {
      "Type": "String",
      "Description": "Email address to notify when new logs are published."
    }
  },
  "Resources": {
    "myTrail2": {
      "DependsOn": [
        "BucketPolicy",
        "TopicPolicy"
      ],
      "Type": "AWS::CloudTrail::Trail",
      "Properties": {
        "IsLogging": true,
        "IsMultiRegionTrail": true,
        "EnableLogFileValidation": true,
        "S3BucketName": {
          "Ref": "S3Bucket"
        },
        "SnsTopicName": {
          "Fn::GetAtt": [
            "Topic",
            "TopicName"
          ]
        }
      }
    },
    "S3Bucket": {
      "DeletionPolicy": "Retain",
      "Type": "AWS::S3::Bucket",
      "Properties": {}
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "myTrail5": {
      "DependsOn": [
        "BucketPolicy",
        "TopicPolicy"
      ],
      "Type": "AWS::CloudTrail::Trail",
      "Properties": {
        "IsMultiRegionTrail": true,
        "S3BucketName": {
          "Ref": "S3Bucket"
        },
        "IsLogging": false
      }
    },
    "myTrail6": {
      "DependsOn": [
        "BucketPolicy",
        "TopicPolicy"
      ],
      "Type": "AWS::CloudTrail::Trail",
      "Properties": {
        "EnableLogFileValidation": false,
        "S3BucketName": {
          "Ref": "S3Bucket"
        },
        "SnsTopicName": "",
        "IsLogging": false,
        "IsMultiRegionTrail": true
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "OperatorEmail": {
      "Description": "Email address to notify when new logs are published.",
      "Type": "String"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  OperatorEmail:
    Description: "Email address to notify when new logs are published."
    Type: String
Resources:
  myTrail3:
    DependsOn:
      - BucketPolicy
      - TopicPolicy
    Type: AWS::CloudTrail::Trail
    Properties:
      S3BucketName:
        Ref: S3Bucket
      IsLogging: false
      IsMultiRegionTrail: true
  myTrail4:
    DependsOn:
      - BucketPolicy
      - TopicPolicy
    Type: AWS::CloudTrail::Trail
    Properties:
      EnableLogFileValidation: false
      S3BucketName:
        Ref: S3Bucket
      SnsTopicName: ""
      IsLogging: false
      IsMultiRegionTrail: true

```