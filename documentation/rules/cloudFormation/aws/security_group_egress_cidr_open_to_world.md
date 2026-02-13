---
title: "Security group egress CIDR open to world"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/security_group_egress_cidr_open_to_world"
  id: "1cc2fbd7-816c-4fbf-ad6d-38a4afa4312a"
  display_name: "Security group egress CIDR open to world"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `1cc2fbd7-816c-4fbf-ad6d-38a4afa4312a`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-security-group-egress.html)

### Description

 Egress rules that allow `0.0.0.0/0` or `::/0` permit unrestricted outbound traffic to the internet. This can enable data exfiltration and communications with malicious command-and-control infrastructure.

In CloudFormation, check `AWS::EC2::SecurityGroupEgress` resources and `AWS::EC2::SecurityGroup` resources’ `Properties.SecurityGroupEgress` entries. `CidrIp` must not be `0.0.0.0/0` and `CidrIpv6` must not be `::/0`. Resources with these values set will be flagged. Restrict egress to specific destination CIDR ranges, reference other security groups, or route outbound traffic through centralized egress controls (NAT gateways, proxies, or firewalls) to meet this requirement.

Secure configuration example:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Restricted outbound access
    SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 10.0.0.0/16
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
      CidrIpv6: 2001:0DB8:1234::/48
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
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "192.0.2.0/24"
          }
        ]
      },
      "Type": "AWS::EC2::SecurityGroup"
    },
    "OutboundRule": {
      "Type": "AWS::EC2::SecurityGroupEgress",
      "Properties": {
        "Description": "TCP",
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 0,
        "CidrIpv6": "2001:0DB8:1234::/48",
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
        },
        "GroupId": {
          "Fn::GetAtt": [
            "TargetSG",
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
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "Description": "TCP",
            "FromPort": 80,
            "ToPort": 80
          }
        ],
        "GroupDescription": "Allow http to client host",
        "VpcId": {
          "Ref": "myVPC"
        }
      }
    },
    "OutboundRule": {
      "Properties": {
        "FromPort": 0,
        "ToPort": 65535,
        "CidrIpv6": "::/0",
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
        "IpProtocol": "tcp"
      },
      "Type": "AWS::EC2::SecurityGroupEgress"
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
        "ToPort": 65535,
        "CidrIpv6": "::/0",
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
      CidrIpv6: ::/0
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