---
title: "TCP UDP protocol network ACL entry allows all ports"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/tcp_or_udp_protocol_network_acl_entry_allows_all_ports"
  id: "f57f849c-883b-4cb7-85e7-f7b199dff163"
  display_name: "TCP UDP protocol network ACL entry allows all ports"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `f57f849c-883b-4cb7-85e7-f7b199dff163`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-network-acl-entry.html#cfn-ec2-networkaclentry-portrange)

### Description

Network ACL entries that allow all TCP or UDP ports significantly broaden the attack surface and can expose many services to network-based attacks and lateral movement.

For `AWS::EC2::NetworkAclEntry` resources where `Protocol` indicates TCP (`6`) or UDP (`17`), the `PortRange` property must be present, include both `From` and `To`, and must not be set to the full range `From: 0` and `To: 65535`. Resources missing `PortRange`, missing the `From`/`To` attributes, or configured to allow `0`–`65535` will be flagged.

To remediate, restrict `PortRange` to specific ports or narrow ranges required by the application.

Secure example with a single allowed port (HTTPS):

```yaml
MyNetworkAclEntry:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: acl-0123456789abcdef0
    RuleNumber: 100
    Protocol: 6
    RuleAction: allow
    Egress: false
    PortRange:
      From: 443
      To: 443
```

## Compliant Code Examples
```yaml
Resources:
  MyNACL9:
    Type: AWS::EC2::NetworkAcl
    Properties:
       VpcId: vpc-1122334455aabbccd
       Tags:
       - Key: Name
         Value: NACLforSSHTraffic
  InboundRule9:
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
  "Resources": {
    "MyNACL9": {
      "Type": "AWS::EC2::NetworkAcl",
      "Properties": {
        "Tags": [
          {
            "Key": "Name",
            "Value": "NACLforSSHTraffic"
          }
        ],
        "VpcId": "vpc-1122334455aabbccd"
      }
    },
    "InboundRule9": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "From": 22,
          "To": 22
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
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
    "InboundRule2": {
      "Properties": {
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "From": 22
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        }
      },
      "Type": "AWS::EC2::NetworkAclEntry"
    },
    "InboundRule3": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "To": 22
        }
      }
    },
    "InboundRule4": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "172.16.0.0/24",
        "NetworkAclId": {
          "Ref": "MyNACL"
        }
      }
    },
    "InboundRule5": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "CidrBlock": "172.16.0.0/24",
        "PortRange": {
          "To": 65535,
          "From": 0
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow"
      }
    }
  }
}

```

```yaml
Resources:
  MyNACL:
    Type: AWS::EC2::NetworkAcl
    Properties:
       VpcId: vpc-1122334455aabbccd
       Tags:
       - Key: Name
         Value: NACLforSSHTraffic
  InboundRule2:
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
  InboundRule3:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 172.16.0.0/24
       PortRange:
         To: 22
  InboundRule4:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 172.16.0.0/24
  InboundRule5:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 172.16.0.0/24
       PortRange:
         From: 0
         To: 65535
```