---
title: "EC2 permissive network ACL protocols"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_permissive_network_acl_protocols"
  id: "03879981-efa2-47a0-a818-c843e1441b88"
  display_name: "EC2 permissive network ACL protocols"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `03879981-efa2-47a0-a818-c843e1441b88`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html)

### Description

 Network ACL entries that permit all protocols or use unsupported protocol values broaden the attack surface and can allow unintended traffic types to reach your instances, increasing risk of reconnaissance, exploitation, and lateral movement. For `AWS::EC2::NetworkAclEntry` resources, the `Protocol` property must be set to one of the numeric values: `6` (TCP), `17` (UDP), `1` (ICMP), or `58` (ICMPv6). Resources missing the `Protocol` property or configured with any other value (for example, `-1`/`all`) will be flagged. 
 
 **Note**: ICMPv6 (`58`) entries must also use an IPv6 CIDR block and include an ICMP type and code.

Secure configuration example:

```yaml
MyNetworkAclEntry:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: !Ref MyNetworkAcl
    RuleNumber: 100
    Protocol: 6
    RuleAction: allow
    CidrBlock: 10.0.0.0/16
    PortRange:
      From: 443
      To: 443
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  MyNACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
       VpcId: vpc-1122334455aabbccd
       Tags:
       - Key: Name
         Value: NACLforSSHTraffic
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
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "InboundRule": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "To": 22,
          "From": 22
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow"
      }
    },
    "MyNACL": {
      "Properties": {
        "VpcId": "vpc-1122334455aabbccd",
        "Tags": [
          {
            "Key": "Name",
            "Value": "NACLforSSHTraffic"
          }
        ]
      },
      "Type": "AWS::EC2::NetworkAcl"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "MyNACL": {
      "Type": "AWS::EC2::NetworkAcl",
      "Properties": {
        "VpcId": "vpc-1122334455aabbccd",
        "Tags": [
          {
            "Key": "Name",
            "Value": "NACLforSSHTraffic"
          }
        ]
      }
    },
    "OutboundRule": {
      "Properties": {
        "CidrBlock": "0.0.0.0/0",
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": -1,
        "Egress": true,
        "RuleAction": "allow"
      },
      "Type": "AWS::EC2::NetworkAclEntry"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  MyNACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
       VpcId: vpc-1122334455aabbccd
       Tags:
       - Key: Name
         Value: NACLforSSHTraffic
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