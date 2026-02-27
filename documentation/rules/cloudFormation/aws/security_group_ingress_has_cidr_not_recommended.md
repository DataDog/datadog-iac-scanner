---
title: "Security group ingress has CIDR not recommended"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/security_group_ingress_has_cidr_not_recommended"
  id: "a3e4e39a-e5fc-4ee9-8cf5-700febfa86dd"
  display_name: "Security group ingress has CIDR not recommended"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `a3e4e39a-e5fc-4ee9-8cf5-700febfa86dd`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html)

### Description

Ingress rules that use single-address CIDRs (IPv4 `/32` or IPv6 `/128`) are brittle. They often indicate hard-coded, single-IP access which can become stale, break when addresses are reassigned, and lead to unintended access or operational disruption.

This check inspects `AWS::EC2::SecurityGroupIngress` resources (`Properties.CidrIp` and `Properties.CidrIpv6`) and `AWS::EC2::SecurityGroup` resources' `Properties.SecurityGroupIngress[].CidrIp` and `CidrIpv6` entries. Any entry containing `/32` (IPv4) or `/128` (IPv6) will be flagged.

To remediate, avoid hard-coding single IPs by using `SourceSecurityGroupId`, AWS managed prefix lists, or appropriately scoped network CIDRs that reflect your trusted network. If a single-IP exception is required, document the justification and maintain a process to review and update it.

Secure configuration example (use security group reference instead of single IP):

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
        SourceSecurityGroupId: !Ref BastionSecurityGroup
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
      "Properties": {
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
        ],
        "SecurityGroupEgress": [
          {
            "ToPort": 80,
            "CidrIp": "192.0.2.0/24",
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80
          }
        ],
        "GroupDescription": "Allow http to client host"
      },
      "Type": "AWS::EC2::SecurityGroup"
    },
    "OutboundRule": {
      "Type": "AWS::EC2::SecurityGroupEgress",
      "Properties": {
        "ToPort": 0,
        "CidrIp": "192.0.2.0/24",
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
        },
        "Description": "TCP",
        "IpProtocol": "tcp",
        "FromPort": 0
      }
    },
    "InboundRule": {
      "Type": "AWS::EC2::SecurityGroupIngress",
      "Properties": {
        "ToPort": 0,
        "CidrIpv6": "2001:0DB8:1234::/48",
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
        "IpProtocol": "tcp",
        "FromPort": 0
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
        "ToPort": 65535,
        "CidrIp": "192.0.2.0/24",
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
        },
        "Description": "TCP",
        "IpProtocol": "tcp",
        "FromPort": 0
      }
    },
    "InboundRule": {
      "Type": "AWS::EC2::SecurityGroupIngress",
      "Properties": {
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
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 65535,
        "CidrIpv6": "::/128"
      }
    },
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "SecurityGroupEgress": [
          {
            "ToPort": 80,
            "CidrIp": "192.0.2.0/24",
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80
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
            "CidrIp": "122.24.0.0/32"
          }
        ]
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
        CidrIp: 122.24.0.0/32
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
      ToPort: 65535
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
      ToPort: 65535
      CidrIpv6: ::/128
      SourceSecurityGroupId:
        Fn::GetAtt:
        - SourceSG
        - GroupId
      GroupId:
        Fn::GetAtt:
        - TargetSG
        - GroupId
```