---
title: "EC2 network ACL duplicate rule"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_network_acl_duplicate_rule"
  id: "045ddb54-cfc5-4abb-9e05-e427b2bc96fe"
  display_name: "EC2 network ACL duplicate rule"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `045ddb54-cfc5-4abb-9e05-e427b2bc96fe`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html#cfn-ec2-networkaclentry-rulenumber)

### Description

 Network ACL entries in the same Network ACL must not reuse the same rule number for the same traffic direction, because duplicate rule numbers in one direction can cause one rule to override another and lead to unintended access or disruption of network traffic.
 
 For `AWS::EC2::NetworkAclEntry` resources, `Properties.RuleNumber` must be unique among entries that reference the same `Properties.NetworkAclId` and share the same direction. Direction is determined by the boolean `Properties.Egress` (`true` = egress, `false` = ingress) or `Properties.Ingress`. The rule flags two distinct resources that reference the same `NetworkAclId` with identical `RuleNumber` and identical direction.
 
 Reusing a `RuleNumber` is acceptable only when one entry is ingress and the other is egress.

Secure configuration examples:

```yaml
MyAclEntryIngress1:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: !Ref MyNetworkAcl
    RuleNumber: 100
    Protocol: -1
    RuleAction: allow
    Egress: false
    CidrBlock: 0.0.0.0/0

MyAclEntryIngress2:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: !Ref MyNetworkAcl
    RuleNumber: 101
    Protocol: -1
    RuleAction: deny
    Egress: false
    CidrBlock: 10.0.0.0/8
```

Allowed example (same rule number only when directions differ):

```yaml
MyAclEntryEgress:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: !Ref MyNetworkAcl
    RuleNumber: 100
    Protocol: -1
    RuleAction: allow
    Egress: true
    CidrBlock: 0.0.0.0/0

MyAclEntryIngress:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: !Ref MyNetworkAcl
    RuleNumber: 100
    Protocol: -1
    RuleAction: deny
    Egress: false
    CidrBlock: 10.0.0.0/8
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyNACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
       VpcId: vpc-1122334455aabbccd
  InboundRule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 172.16.0.0/24
       PortRange:
         From: 22
         To: 22
  OutboundRule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: -1
       Egress: true
       RuleAction: allow
       CidrBlock: 0.0.0.0/0

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyNACL": {
      "Type": "AWS::EC2::NetworkAcl",
      "Properties": {
        "VpcId": "vpc-1122334455aabbccd"
      }
    },
    "InboundRule": {
      "Properties": {
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "From": 22,
          "To": 22
        }
      },
      "Type": "AWS::EC2::NetworkAclEntry"
    },
    "OutboundRule": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": -1,
        "Egress": true,
        "RuleAction": "allow",
        "CidrBlock": "0.0.0.0/0"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyNACL": {
      "Properties": {
        "VpcId": "vpc-1122334455aabbccd"
      },
      "Type": "AWS::EC2::NetworkAcl"
    },
    "InboundRule": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "Egress": true,
        "RuleAction": "allow",
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "From": 22,
          "To": 22
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6
      }
    },
    "OutboundRule": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": -1,
        "Egress": true,
        "RuleAction": "allow",
        "CidrBlock": "0.0.0.0/0"
      }
    },
    "MyNACL2": {
      "Type": "AWS::EC2::NetworkAcl",
      "Properties": {
        "VpcId": "vpc-1122334455aabbccdd"
      }
    },
    "InboundRule2": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "From": 22,
          "To": 22
        },
        "NetworkAclId": {
          "Ref": "MyNACL2"
        },
        "RuleNumber": "112",
        "Protocol": 6,
        "Ingress": true,
        "RuleAction": "allow"
      }
    },
    "OutboundRule2": {
      "Properties": {
        "Ingress": true,
        "RuleAction": "allow",
        "CidrBlock": "0.0.0.0/0",
        "NetworkAclId": {
          "Ref": "MyNACL2"
        },
        "RuleNumber": "112",
        "Protocol": -1
      },
      "Type": "AWS::EC2::NetworkAclEntry"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyNACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
       VpcId: vpc-1122334455aabbccd
  InboundRule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       Egress: true
       RuleAction: allow
       CidrBlock: 172.16.0.0/24
       PortRange:
         From: 22
         To: 22
  OutboundRule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: -1
       Egress: true
       RuleAction: allow
       CidrBlock: 0.0.0.0/0
  MyNACL2:
    Type: AWS::EC2::NetworkAcl
    Properties:
       VpcId: vpc-1122334455aabbccdd
  InboundRule2:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL2
       RuleNumber: "112"
       Protocol: 6
       Ingress: true
       RuleAction: allow
       CidrBlock: 172.16.0.0/24
       PortRange:
         From: 22
         To: 22
  OutboundRule2:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL2
       RuleNumber: "112"
       Protocol: -1
       Ingress: true
       RuleAction: allow
       CidrBlock: 0.0.0.0/0

```