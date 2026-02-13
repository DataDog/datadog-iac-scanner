---
title: "Security groups with exposed admin ports"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/security_groups_with_exhibited_admin_ports"
  id: "cdbb0467-2957-4a77-9992-7b55b29df7b7"
  display_name: "Security groups with exposed admin ports"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `cdbb0467-2957-4a77-9992-7b55b29df7b7`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

Security groups must not allow inbound access from the public internet (`0.0.0.0/0`) to high-risk service ports. Public exposure of these services increases the risk of brute-force attacks, exploitation of known vulnerabilities, and unauthorized access or lateral movement.

This rule inspects `AWS::EC2::SecurityGroup` resources and flags `SecurityGroupIngress` entries where `CidrIp` is `0.0.0.0/0` and either `FromPort` or `ToPort` equals one of `20`, `21`, `22`, `23`, `115`, `137`, `138`, `139`, `2049`, or `3389`.

To remediate, restrict `CidrIp` to trusted CIDR ranges, use security group references, or place access behind a bastion host or VPN. Remove or narrow rules for these ports when possible.

**Note**: This check evaluates IPv4 `CidrIp` entries only. Ensure any IPv6 (`::/0`) rules are likewise restricted.

Secure example restricting SSH to a trusted subnet:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: SSH access from admin network
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: 203.0.113.0/24
```

## Compliant Code Examples
```yaml
Resources:
  Ec2Instance:
    Type: 'AWS::EC2::Instance'
    Properties:
      SecurityGroups:
        - !Ref InstanceSecurityGroup
      KeyName: mykey
      ImageId: ''
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Allow http to client host
        VpcId:
          Ref: myVPC
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 127.0.0.1/32
        SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 127.0.0.1/33
```

```json
{
  "Resources": {
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "SecurityGroups": [
          "InstanceSecurityGroup"
        ],
        "KeyName": "mykey",
        "ImageId": ""
      }
    },
    "InstanceSecurityGroup": {
      "Properties": {
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "127.0.0.1/32"
          }
        ],
        "SecurityGroupEgress": [
          {
            "CidrIp": "127.0.0.1/33",
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80
          }
        ],
        "GroupDescription": "Allow http to client host"
      },
      "Type": "AWS::EC2::SecurityGroup"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Allow http to client host
        VpcId:
          Ref: myVPC
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 11.22.33.44/32
```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "",
        "SecurityGroups": [
          "InstanceSecurityGroup"
        ],
        "KeyName": "mykey"
      }
    },
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "FromPort": 20,
            "ToPort": 20
          }
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "GroupDescription": "Allow http to client host"
      }
    }
  }
}

```

```yaml
Resources:
  Ec2Instance:
    Type: 'AWS::EC2::Instance'
    Properties:
      SecurityGroups:
        - !Ref InstanceSecurityGroup
      KeyName: mykey
      ImageId: ''
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Allow http to client host
        VpcId:
          Ref: myVPC
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 20
          ToPort: 20
          CidrIp: 0.0.0.0/0
        SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
```