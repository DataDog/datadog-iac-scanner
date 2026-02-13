---
title: "Security group with unrestricted access to SSH"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/security_groups_with_unrestricted_access_to_ssh"
  id: "6e856af2-62d7-4ba2-adc1-73b62cef9cc1"
  display_name: "Security group with unrestricted access to SSH"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `6e856af2-62d7-4ba2-adc1-73b62cef9cc1`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

 Allowing SSH (TCP port `22`) from the public internet (`0.0.0.0/0`) exposes instances to brute-force attacks, credential theft, lateral movement, and unauthorized access. In CloudFormation `AWS::EC2::SecurityGroup` resources, any `Properties.SecurityGroupIngress` entry with `CidrIp: 0.0.0.0/0` and `FromPort` or `ToPort` equal to `22` will be flagged.

To remediate, restrict SSH ingress to specific trusted IP ranges, use a bastion/jump host, or adopt AWS Systems Manager Session Manager instead of opening port `22`. Resources containing the insecure ingress entry will be reported.

Secure configuration example (restrict SSH to a single IP):

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Allow SSH from admin IP only
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: 203.0.113.4/32
```

Note: this rule specifically matches ingress entries where `FromPort == 22` or `ToPort == 22`; port ranges that include 22 but do not have 22 as an endpoint may not be detected by this check.


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
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow http to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "127.0.0.1/32",
            "IpProtocol": "tcp"
          }
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "127.0.0.1/33"
          }
        ]
      }
    },
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "SecurityGroups": [
          "InstanceSecurityGroup"
        ],
        "KeyName": "mykey",
        "ImageId": ""
      }
    }
  }
}

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
      "Properties": {
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "GroupDescription": "Allow http to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "ToPort": 22,
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "FromPort": 22
          }
        ]
      },
      "Type": "AWS::EC2::SecurityGroup"
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
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
```