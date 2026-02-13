---
title: "Unrestricted security group ingress"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/unrestricted_security_group_ingress"
  id: "4a1e6b34-1008-4e61-a5f2-1f7c276f8d14"
  display_name: "Unrestricted security group ingress"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `4a1e6b34-1008-4e61-a5f2-1f7c276f8d14`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html)

### Description

 Security groups must not allow ingress from the entire internet (`0.0.0.0/0` or `::/0`) because such wide-open rules expose instances and services to unauthorized access, brute-force attempts, and remote exploitation.

This rule checks `AWS::EC2::SecurityGroupIngress` resources (`Properties.CidrIp` / `Properties.CidrIpv6`) and `AWS::EC2::SecurityGroup` resources' `Properties.SecurityGroupIngress` entries. `CidrIp` must not be `0.0.0.0/0` and `CidrIpv6` must not be `::/0`. Resources with those values will be flagged.

To remediate, restrict access to specific trusted CIDR ranges, use VPC-only ranges, prefix lists, or reference other security groups via `SourceSecurityGroupId`/`SourceSecurityGroupOwnerId`.

Secure examples (CloudFormation YAML):

```yaml
MyRestrictedIngress:
  Type: AWS::EC2::SecurityGroupIngress
  Properties:
    GroupId: !Ref MySecurityGroup
    IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 10.0.0.0/16
```

```yaml
MySGToSGIngress:
  Type: AWS::EC2::SecurityGroupIngress
  Properties:
    GroupId: !Ref MySecurityGroup
    IpProtocol: tcp
    FromPort: 443
    ToPort: 443
    SourceSecurityGroupId: sg-0123456789abcdef0
```


## Compliant Code Examples
```yaml
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow http to client host
      VpcId:
         Ref: myVPC
      SecurityGroupIngress:
      - IpProtocol: tcp
        Description: TCP
        FromPort: 80
        ToPort: 80
        CidrIp: 192.0.2.0/24
      SecurityGroupEgress:
      - IpProtocol: tcp
        Description: TCP
        FromPort: 80
        ToPort: 80
        CidrIp: 192.0.2.0/24
  OutboundRule:
    Type: AWS::EC2::SecurityGroupEgress
    Properties:
      Description: TCP
      IpProtocol: tcp
      FromPort: 0
      ToPort: 0
      CidrIp: 192.0.2.0/24
      DestinationSecurityGroupId:
        Fn::GetAtt:
        - TargetSG
        - GroupId
      GroupId:
        Fn::GetAtt:
        - SourceSG
        - GroupId
  InboundRule:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      Description: TCP
      IpProtocol: tcp
      FromPort: 0
      ToPort: 0
      CidrIpv6: 2001:0DB8:1234::/48
      SourceSecurityGroupId:
        Fn::GetAtt:
        - SourceSG
        - GroupId
      GroupId:
        Fn::GetAtt:
        - TargetSG
        - GroupId
```

```json
{
  "Resources": {
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "192.0.2.0/24"
          }
        ],
        "GroupDescription": "Allow http to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "192.0.2.0/24"
          }
        ]
      }
    },
    "OutboundRule": {
      "Type": "AWS::EC2::SecurityGroupEgress",
      "Properties": {
        "GroupId": {
          "Fn::GetAtt": [
            "SourceSG",
            "GroupId"
          ]
        },
        "Description": "TCP",
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 0,
        "CidrIp": "192.0.2.0/24",
        "DestinationSecurityGroupId": {
          "Fn::GetAtt": [
            "TargetSG",
            "GroupId"
          ]
        }
      }
    },
    "InboundRule": {
      "Type": "AWS::EC2::SecurityGroupIngress",
      "Properties": {
        "GroupId": {
          "Fn::GetAtt": [
            "TargetSG",
            "GroupId"
          ]
        },
        "Description": "TCP",
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 0,
        "CidrIpv6": "2001:0DB8:1234::/48",
        "SourceSecurityGroupId": {
          "Fn::GetAtt": [
            "SourceSG",
            "GroupId"
          ]
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
    "OutboundRule": {
      "Type": "AWS::EC2::SecurityGroupEgress",
      "Properties": {
        "Description": "TCP",
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 65535,
        "CidrIp": "0.0.0.0/0",
        "DestinationSecurityGroupId": {
          "Fn::GetAtt": [
            "TargetSG",
            "GroupId"
          ]
        },
        "GroupId": {
          "Fn::GetAtt": [
            "SourceSG",
            "GroupId"
          ]
        }
      }
    },
    "InboundRule": {
      "Type": "AWS::EC2::SecurityGroupIngress",
      "Properties": {
        "FromPort": 0,
        "ToPort": 65535,
        "CidrIpv6": "::/0",
        "SourceSecurityGroupId": {
          "Fn::GetAtt": [
            "SourceSG",
            "GroupId"
          ]
        },
        "GroupId": {
          "Fn::GetAtt": [
            "TargetSG",
            "GroupId"
          ]
        },
        "Description": "TCP",
        "IpProtocol": "tcp"
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
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80
          }
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "Description": "TCP",
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
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow http to client host
      VpcId:
         Ref: myVPC
      SecurityGroupIngress:
      - IpProtocol: tcp
        Description: TCP
        FromPort: 80
        ToPort: 80
        CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
      - IpProtocol: tcp
        Description: TCP
        FromPort: 80
        ToPort: 80
        CidrIp: 0.0.0.0/0
  OutboundRule:
    Type: AWS::EC2::SecurityGroupEgress
    Properties:
      Description: TCP
      IpProtocol: tcp
      FromPort: 0
      ToPort: 65535
      CidrIp: 0.0.0.0/0
      DestinationSecurityGroupId:
        Fn::GetAtt:
        - TargetSG
        - GroupId
      GroupId:
        Fn::GetAtt:
        - SourceSG
        - GroupId
  InboundRule:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      Description: TCP
      IpProtocol: tcp
      FromPort: 0
      ToPort: 65535
      CidrIpv6: ::/0
      SourceSecurityGroupId:
        Fn::GetAtt:
        - SourceSG
        - GroupId
      GroupId:
        Fn::GetAtt:
        - TargetSG
        - GroupId
```