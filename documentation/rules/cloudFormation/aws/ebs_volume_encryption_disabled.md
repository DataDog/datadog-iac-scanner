---
title: "EBS volume encryption disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ebs_volume_encryption_disabled"
  id: "80b7ac3f-d2b7-4577-9b10-df7913497162"
  display_name: "EBS volume encryption disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `80b7ac3f-d2b7-4577-9b10-df7913497162`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-ebs-volume.html)

### Description

Amazon EBS volumes must be encrypted to protect data at rest from unauthorized access and to prevent sensitive information from being exposed via unencrypted snapshots or compromised storage. In CloudFormation, the `Encrypted` property on `AWS::EC2::Volume` resources must be defined and set to `true`. Resources that omit the `Encrypted` property or have `Encrypted` set to `false` will be flagged. Optionally specify `KmsKeyId` to use a customer-managed AWS KMS key for encryption and key rotation policies.

Secure configuration example:

```yaml
MyVolume:
  Type: AWS::EC2::Volume
  Properties:
    AvailabilityZone: us-east-1a
    Size: 100
    Encrypted: true
    KmsKeyId: arn:aws:kms:us-east-1:123456789012:key/abcd-1234-ef56-...
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Volume"
Resources:
  NewVolume:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      Encrypted: true
      AvailabilityZone: !GetAtt Ec2Instance.AvailabilityZone
      Tags:
        - Key: MyTag
          Value: TagValue
    DeletionPolicy: Snapshot

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Volume",
  "Resources": {
    "NewVolume": {
      "Type": "AWS::EC2::Volume",
      "Properties": {
        "Encrypted": true,
        "AvailabilityZone": "Ec2Instance.AvailabilityZone",
        "Tags": [
          {
            "Key": "MyTag",
            "Value": "TagValue"
          }
        ],
        "Size": 100
      },
      "DeletionPolicy": "Snapshot"
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Volume 02"
Resources:
  NewVolume02:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      AvailabilityZone: !GetAtt Ec2Instance.AvailabilityZone
      Tags:
        - Key: MyTag
          Value: TagValue
    DeletionPolicy: Snapshot

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Volume",
  "Resources": {
    "NewVolume": {
      "Type": "AWS::EC2::Volume",
      "Properties": {
        "Tags": [
          {
            "Key": "MyTag",
            "Value": "TagValue"
          }
        ],
        "Size": 100,
        "Encrypted": false,
        "AvailabilityZone": "Ec2Instance.AvailabilityZone"
      },
      "DeletionPolicy": "Snapshot"
    }
  }
}

```

```json
{
  "Description": "Volume 02",
  "Resources": {
    "NewVolume02": {
      "Type": "AWS::EC2::Volume",
      "Properties": {
        "Size": 100,
        "AvailabilityZone": "Ec2Instance.AvailabilityZone",
        "Tags": [
          {
            "Key": "MyTag",
            "Value": "TagValue"
          }
        ]
      },
      "DeletionPolicy": "Snapshot"
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```