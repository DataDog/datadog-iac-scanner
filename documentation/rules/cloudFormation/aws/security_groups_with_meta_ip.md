---
title: "Security groups with meta IP"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/security_groups_with_meta_ip"
  id: "adcd0082-e90b-4b63-862b-21899f6e6a48"
  display_name: "Security groups with meta IP"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `adcd0082-e90b-4b63-862b-21899f6e6a48`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

 Security groups must not allow ingress from `0.0.0.0/0` across all ports. An all-ports public rule exposes instances to the internet and enables indiscriminate port scanning and brute-force attacks.

In CloudFormation, check `Resources.*.Properties.SecurityGroupIngress` entries (and standalone `AWS::EC2::SecurityGroupIngress` resources) and ensure no rule has `CidrIp: 0.0.0.0/0` with `FromPort: 0` and `ToPort: 65535`. Resources containing such an entry will be flagged.

To remediate, restrict `CidrIp` to trusted IP ranges, narrow the port range to only the required ports (for example, `80` and `443`), or reference other security groups or load balancers to provide controlled access.

Secure configuration example (allow only specific ports):

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
      "Properties": {
        "SecurityGroups": [
          "InstanceSecurityGroup"
        ],
        "KeyName": "mykey",
        "ImageId": ""
      },
      "Type": "AWS::EC2::Instance"
    },
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow http to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "ToPort": 80,
            "CidrIp": "127.0.0.1/32",
            "IpProtocol": "tcp",
            "FromPort": 80
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
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "Ec2Instance": {
      "Properties": {
        "SecurityGroups": [
          "InstanceSecurityGroup"
        ],
        "KeyName": "mykey",
        "ImageId": ""
      },
      "Type": "AWS::EC2::Instance"
    },
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow http to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "FromPort": 0,
            "ToPort": 65535,
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp"
          }
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0"
          }
        ]
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
          FromPort: 0
          ToPort: 65535
          CidrIp: 0.0.0.0/0
        SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
```