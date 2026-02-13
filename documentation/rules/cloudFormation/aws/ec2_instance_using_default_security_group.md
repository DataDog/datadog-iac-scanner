---
title: "EC2 instance using default security group"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_instance_using_default_security_group"
  id: "08b81bb3-0985-4023-8602-b606ad81d279"
  display_name: "EC2 instance using default security group"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `08b81bb3-0985-4023-8602-b606ad81d279`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-instance.html#cfn-ec2-instance-securitygroups)

### Description

Attaching EC2 instances to the VPC default security group increases risk because the default group is typically shared, often permits broad intra‑VPC traffic, and cannot be tightly scoped, which facilitates lateral movement and unintended access.
 
 This rule checks `AWS::EC2::Instance` resources and inspects the `SecurityGroups` and `SecurityGroupIds` properties. Any entry that references or names the default security group (case‑insensitive match for `default`) will be flagged. The check evaluates both literal values and `Ref` references, so entries containing `default` or pointing to a default security group resource are considered noncompliant.
 
 Use explicit, purpose‑built security groups with restrictive ingress/egress rules and reference those group IDs or logical names instead of the default group.

Secure configuration example:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Web server security group
    VpcId: !Ref MyVPC
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 0.0.0.0/0

MyInstance:
  Type: AWS::EC2::Instance
  Properties:
    ImageId: ami-0abcdef1234567890
    InstanceType: t3.micro
    SecurityGroupIds:
      - !Ref MySecurityGroup
```

## Compliant Code Examples
```yaml
 Resources:
  MyEC2Instancee: 
      Type: AWS::EC2::Instance
      Properties: 
        ImageId: "ami-79fd7eee"
        KeyName: "testkey"
        SecurityGroups: 
          - !Ref my_sg
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

```json
{
  "Resources": {
    "MyEC2Instancee": {
      "Properties": {
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/sdm",
            "Ebs": {
              "DeleteOnTermination": "false",
              "Iops": "200",
              "VolumeSize": "20",
              "VolumeType": "io1"
            }
          },
          {
            "DeviceName": "/dev/sdk",
            "NoDevice": {}
          }
        ],
        "ImageId": "ami-79fd7eee",
        "KeyName": "testkey",
        "SecurityGroups": [
          "my_sg"
        ]
      },
      "Type": "AWS::EC2::Instance"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "MyEC2Instance": {
      "Properties": {
        "BlockDeviceMappings": [
          {
            "DeviceName": "/dev/sdm",
            "Ebs": {
              "DeleteOnTermination": "false",
              "Iops": "200",
              "VolumeSize": "20",
              "VolumeType": "io1"
            }
          },
          {
            "DeviceName": "/dev/sdk",
            "NoDevice": {}
          }
        ],
        "ImageId": "ami-79fd7eee",
        "KeyName": "testkey",
        "SecurityGroups": [
          "default"
        ]
      },
      "Type": "AWS::EC2::Instance"
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
        SecurityGroups: 
          - !Ref default
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