---
title: "EC2 not EBS optimized"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_not_ebs_optimized"
  id: "8dd0ff1f-0da4-48df-9bb3-7f338ae36a40"
  display_name: "EC2 not EBS optimized"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `8dd0ff1f-0da4-48df-9bb3-7f338ae36a40`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-ebsoptimized)

### Description

EC2 instances should be EBS-optimized to ensure dedicated throughput and reduced I/O contention between instance network traffic and Amazon EBS volumes. This improves disk performance, lowers latency spikes, and helps maintain application availability under load.
 
 For `AWS::EC2::Instance` resources, the `Properties.EbsOptimized` property must be defined and set to `true` for instance types that are not EBS-optimized by default. Resources missing `EbsOptimized` or with `EbsOptimized` set to `false` will be flagged. Instance types that are EBS-optimized by default are exempt.
 
 **Note**: If `InstanceType` is omitted, CloudFormation defaults to `m1.small`, which is not EBS-optimized by default and should have `EbsOptimized` set to `true` explicitly set.

Secure configuration example:

```yaml
MyInstance:
  Type: AWS::EC2::Instance
  Properties:
    InstanceType: m5.large
    EbsOptimized: true
```

## Compliant Code Examples
```yaml
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"
        - DeviceName: "/dev/sdk"
          NoDevice: {}
      EbsOptimized: true

```

```json
{
  "Resources": {
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "InstanceType": "t3.nano",
        "ImageId": "ami-79fd7eee",
        "KeyName": "testkey",
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/sdm",
            "Ebs": {
              "VolumeType": "io1",
              "Iops": "200",
              "DeleteOnTermination": "false",
              "VolumeSize": "20"
            }
          },
          {
            "DeviceName": "/dev/sdk",
            "NoDevice": {}
          }
        ]
      }
    }
  }
}

```

```json
{
  "Resources": {
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-79fd7eee",
        "KeyName": "testkey",
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/sdm",
            "Ebs": {
              "VolumeType": "io1",
              "Iops": "200",
              "DeleteOnTermination": "false",
              "VolumeSize": "20"
            }
          },
          {
            "DeviceName": "/dev/sdk",
            "NoDevice": {}
          }
        ],
        "EbsOptimized": true
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-79fd7eee",
        "KeyName": "testkey",
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/sdm",
            "Ebs": {
              "VolumeType": "io1",
              "Iops": "200",
              "DeleteOnTermination": "false",
              "VolumeSize": "20"
            }
          },
          {
            "DeviceName": "/dev/sdk",
            "NoDevice": {}
          }
        ]
      }
    }
  }
}

```

```yaml
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"
        - DeviceName: "/dev/sdk"
          NoDevice: {}
      EbsOptimized: false

```

```yaml
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t2.small
      ImageId: "ami-79fd7eee"
      KeyName: "testkey"
      BlockDeviceMappings:
        - DeviceName: "/dev/sdm"
          Ebs:
            VolumeType: "io1"
            Iops: "200"
            DeleteOnTermination: "false"
            VolumeSize: "20"
        - DeviceName: "/dev/sdk"
          NoDevice: {}

```