---
title: "EC2 network ACL overlapping ports"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_network_acl_overlapping_ports"
  id: "77b6f1e2-bde4-4a6a-ae7e-a40659ff1576"
  display_name: "EC2 network ACL overlapping ports"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `77b6f1e2-bde4-4a6a-ae7e-a40659ff1576`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-networkaclentry-portrange.html)

### Description

 Network ACL entries with overlapping port ranges can make rules ineffective or cause unintended allow/deny behavior, increasing the risk of unauthorized access or service disruption. This check inspects `AWS::EC2::NetworkAclEntry` resources and their `Properties.PortRange.From` and `Properties.PortRange.To` values. Each entry must define a port range that does not intersect with any other `AWS::EC2::NetworkAclEntry` port range in the same template.
 
 Resources missing `PortRange`, with `From` greater than `To`, or with ranges that share any port will be flagged as a misconfiguration. 
 
 Secure configuration example with distinct, non-overlapping port ranges:

```yaml
AclEntry1:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: acl-01234567
    Protocol: 6
    RuleAction: allow
    Egress: false
    PortRange:
      From: 80
      To: 80

AclEntry2:
  Type: AWS::EC2::NetworkAclEntry
  Properties:
    NetworkAclId: acl-01234567
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
         From: 13
         To: 22
  OutboundRule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 173.20.0.0/24
       PortRange:
         From: 24
         To: 25

```

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
          "From": 13,
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
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "173.20.0.0/24",
        "PortRange": {
          "From": 24,
          "To": 25
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
    "Default": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "150.20.0.0/24",
        "PortRange": {
          "From": 1,
          "To": 2
        }
      }
    },
    "Match": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "PortRange": {
          "From": 3,
          "To": 5
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "121.20.0.0/24"
      }
    },
    "EqualMatch": {
      "Properties": {
        "CidrBlock": "120.20.0.0/24",
        "PortRange": {
          "From": 3,
          "To": 5
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow"
      },
      "Type": "AWS::EC2::NetworkAclEntry"
    },
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
    "InboundRule": {
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
          "From": 13,
          "To": 22
        }
      }
    },
    "OutboundRule": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "PortRange": {
          "From": 12,
          "To": 20
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "173.20.0.0/24"
      }
    },
    "OutboundTests": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6,
        "RuleAction": "allow",
        "CidrBlock": "175.20.0.0/24",
        "PortRange": {
          "From": 20,
          "To": 25
        }
      }
    },
    "InboundTests": {
      "Type": "AWS::EC2::NetworkAclEntry",
      "Properties": {
        "RuleAction": "allow",
        "CidrBlock": "151.20.0.0/24",
        "PortRange": {
          "From": 6,
          "To": 13
        },
        "NetworkAclId": {
          "Ref": "MyNACL"
        },
        "RuleNumber": 100,
        "Protocol": 6
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
         From: 13
         To: 22
  OutboundRule:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 173.20.0.0/24
       PortRange:
         From: 12
         To: 20
  OutboundTests:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 175.20.0.0/24
       PortRange:
         From: 20
         To: 25
  InboundTests:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 151.20.0.0/24
       PortRange:
         From: 6
         To: 13
  Default:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 150.20.0.0/24
       PortRange:
         From: 1
         To: 2
  Match:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 121.20.0.0/24
       PortRange:
         From: 3
         To: 5
  EqualMatch:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
       NetworkAclId:
         Ref: MyNACL
       RuleNumber: 100
       Protocol: 6
       RuleAction: allow
       CidrBlock: 120.20.0.0/24
       PortRange:
         From: 3
         To: 5

```