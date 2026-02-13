---
title: "Kinesis SSE not configured"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/kinesis_sse_not_configured"
  id: "7f65be75-90ab-4036-8c2a-410aef7bb650"
  display_name: "Kinesis SSE not configured"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `7f65be75-90ab-4036-8c2a-410aef7bb650`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html)

### Description

Kinesis streams must have server-side encryption enabled to protect data at rest and reduce the risk of sensitive records being exposed through compromised storage, snapshots, or insider access. In AWS CloudFormation, `AWS::Kinesis::Stream` resources must include the `Properties.StreamEncryption` object with `EncryptionType` and `KeyId` defined. Resources missing `StreamEncryption` or with `StreamEncryption.EncryptionType` or `StreamEncryption.KeyId` undefined will be flagged as insecure.

Secure CloudFormation example:

```yaml
MyKinesisStream:
  Type: AWS::Kinesis::Stream
  Properties:
    Name: my-stream
    ShardCount: 1
    StreamEncryption:
      EncryptionType: KMS
      KeyId: arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-ab12-3456cdef7890
```

## Compliant Code Examples
```yaml
Resources:
  EventStream:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: EventStream
      RetentionPeriodHours: 24
      ShardCount: 1
      StreamEncryption:
            EncryptionType: KMS
            KeyId: !Ref myKey
      Tags:
        - Key: Name
          Value: !Sub ${EnvironmentName}-EventStream-${AWS::Region}
```

```json
{
  "Resources": {
    "EventStream": {
      "Type": "AWS::Kinesis::Stream",
      "Properties": {
        "Tags": [
          {
            "Key": "Name",
            "Value": "${EnvironmentName}-EventStream-${AWS::Region}"
          }
        ],
        "Name": "EventStream",
        "RetentionPeriodHours": 24,
        "ShardCount": 1,
        "StreamEncryption": {
          "EncryptionType": "KMS",
          "KeyId": "myKey"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "EventStream1": {
      "Type": "AWS::Kinesis::Stream",
      "Properties": {
        "Name": "EventStream",
        "RetentionPeriodHours": 24,
        "ShardCount": 1,
        "StreamEncryption": {
          "EncryptionType": "KMS"
        },
        "Tags": [
          {
            "Key": "Name",
            "Value": "${EnvironmentName}-EventStream-${AWS::Region}"
          }
        ]
      }
    },
    "EventStream2": {
      "Type": "AWS::Kinesis::Stream",
      "Properties": {
        "Name": "EventStream",
        "RetentionPeriodHours": 24,
        "ShardCount": 1,
        "StreamEncryption": {
          "KeyId": "myKey"
        },
        "Tags": [
          {
            "Key": "Name",
            "Value": "${EnvironmentName}-EventStream-${AWS::Region}"
          }
        ]
      }
    },
    "EventStream3": {
      "Type": "AWS::Kinesis::Stream",
      "Properties": {
        "Name": "EventStream",
        "RetentionPeriodHours": 24,
        "ShardCount": 1,
        "Tags": [
          {
            "Key": "Name",
            "Value": "${EnvironmentName}-EventStream-${AWS::Region}"
          }
        ]
      }
    }
  }
}

```

```yaml
Resources:
  EventStream1:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: EventStream
      RetentionPeriodHours: 24
      ShardCount: 1
      StreamEncryption:
            EncryptionType: KMS
      Tags:
        - Key: Name
          Value: !Sub ${EnvironmentName}-EventStream-${AWS::Region}
  EventStream2:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: EventStream
      RetentionPeriodHours: 24
      ShardCount: 1
      StreamEncryption:
            KeyId: !Ref myKey
      Tags:
        - Key: Name
          Value: !Sub ${EnvironmentName}-EventStream-${AWS::Region}
  EventStream3:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: EventStream
      RetentionPeriodHours: 24
      ShardCount: 1
      Tags:
        - Key: Name
          Value: !Sub ${EnvironmentName}-EventStream-${AWS::Region}


```