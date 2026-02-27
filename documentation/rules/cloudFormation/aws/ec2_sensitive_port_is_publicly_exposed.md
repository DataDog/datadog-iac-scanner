---
title: "EC2 sensitive port is publicly exposed"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_sensitive_port_is_publicly_exposed"
  id: "494b03d3-bf40-4464-8524-7c56ad0700ed"
  display_name: "EC2 sensitive port is publicly exposed"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `494b03d3-bf40-4464-8524-7c56ad0700ed`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

Security group ingress rules must not expose known sensitive service ports to the entire internet (for example, `0.0.0.0/0` or `::/0`) because this makes EC2 instances reachable for unauthorized access, brute-force attacks, and exploitation of network services.
 
 This check inspects `AWS::EC2::SecurityGroup` resources that are attached to `AWS::EC2::Instance` (via the instance's `SecurityGroups` property). It flags `SecurityGroupIngress` entries where the `CidrIp` value ends with `/0` and the `IpProtocol` plus `FromPort`–`ToPort` range includes known sensitive ports (for example, SSH `22`, RDP `3389`, and common database ports). The rule evaluates `IpProtocol` values of `-1`/`ALL` as both TCP and UDP and supports port ranges when mapping to sensitive services.
 
 Remediate by restricting `CidrIp` to specific trusted CIDR ranges, using source security groups, or placing access behind bastion hosts or VPNs.

Secure configuration example:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Allow SSH from admin network
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: 10.0.0.0/24
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Resources:
  SafeSecGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 127.0.0.1/32
      GroupDescription: Allow http and ssh
      VpcId: my-vpc
      SecurityGroupIngress:
        - FromPort: 80
          ToPort: 80
          CidrIp: 127.0.0.1/32
          IpProtocol: tcp
        - ToPort: 77
          CidrIp: 127.0.0.1/32
          IpProtocol: all
          FromPort: 77
  MyNegativeEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroups:
        - SafeSecGroup
      KeyName: my-new-rsa-key
      ImageId: ami-79fd7eee
      InstanceType: t3.medium

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "SafeSecGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow http and ssh",
        "VpcId": "my-vpc",
        "SecurityGroupIngress": [
          {
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "127.0.0.1/32",
            "IpProtocol": "tcp"
          },
          {
            "ToPort": 77,
            "CidrIp": "127.0.0.1/32",
            "IpProtocol": "all",
            "FromPort": 77
          }
        ],
        "SecurityGroupEgress": [
          {
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "127.0.0.1/32",
            "IpProtocol": "tcp"
          }
        ]
      }
    },
    "MyNegativeEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "SecurityGroups": [
          "SafeSecGroup"
        ],
        "KeyName": "my-new-rsa-key",
        "ImageId": "ami-79fd7eee",
        "InstanceType": "t3.medium"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Resources:
  UnsafeSecGroup02:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow http and mysql
      VpcId: my-vpc
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 127.0.0.1/32
        - ToPort: 1434
          CidrIp: 10.0.0.1/0
          IpProtocol: tcp
          FromPort: 1433
        - IpProtocol: tcp
          FromPort: 150
          ToPort: 180
          CidrIp: 10.0.0.1/0
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
  EC2Instance02:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t3.medium
      SecurityGroups:
        - UnsafeSecGroup02
      KeyName: my-new-rsa-key
      ImageId: ami-79fd7eee

```

```yaml
AWSTemplateFormatVersion: 2010-09-09T00:00:00Z
Resources:
  UnsafeSecGroup03:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
      GroupDescription: Allow http and hadoop
      VpcId: my-vpc
      SecurityGroupIngress:
        - ToPort: 80
          CidrIp: 0.0.0.0/0
          IpProtocol: tcp
          FromPort: 80
        - ToPort: 9000
          CidrIp: 10.0.0.1/0
          IpProtocol: tcp
          FromPort: 9000
  EC2Instance03:
    Type: AWS::EC2::Instance
    Properties:
      SecurityGroups:
        - UnsafeSecGroup03
      KeyName: my-new-rsa-key
      ImageId: ami-79fd7eee
      InstanceType: t3.medium

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "UnsafeSecGroup01": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "SecurityGroupEgress": [
          {
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp"
          }
        ],
        "GroupDescription": "Allow http and redis",
        "VpcId": "my-vpc",
        "SecurityGroupIngress": [
          {
            "FromPort": 8080,
            "ToPort": 8080,
            "CidrIp": "127.0.0.1/32",
            "IpProtocol": "tcp"
          },
          {
            "IpProtocol": "tcp",
            "FromPort": 6379,
            "ToPort": 6379,
            "CidrIp": "10.0.0.1/0"
          }
        ]
      }
    },
    "EC2Instance01": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-79fd7eee",
        "InstanceType": "t3.medium",
        "SecurityGroups": [
          "UnsafeSecGroup01"
        ],
        "KeyName": "my-new-rsa-key"
      }
    }
  }
}

```