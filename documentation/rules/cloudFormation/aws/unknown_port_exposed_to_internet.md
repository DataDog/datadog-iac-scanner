---
title: "Unknown port exposed to internet"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/unknown_port_exposed_to_internet"
  id: "829ce3b8-065c-41a3-ad57-e0accfea82d2"
  display_name: "Unknown port exposed to internet"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `829ce3b8-065c-41a3-ad57-e0accfea82d2`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

Security groups must not expose unknown TCP ports to the entire internet because unknown or unapproved ports can host undocumented services and increase the attack surface for scanning and exploitation.

For `AWS::EC2::SecurityGroup` resources, this rule inspects each `SecurityGroupIngress` entry and flags entries that use `CidrIp: 0.0.0.0/0` or `CidrIpv6: ::/0` together with `FromPort`/`ToPort` values that are not present in the known TCP ports map. The check treats a missing or unrecognized `FromPort` or `ToPort` as a violation and also flags ranges where any port in `FromPort..ToPort` is unknown.

To remediate, restrict the CIDR to trusted IP ranges, use explicit approved ports, or reference other security groups instead.

Secure example (allow only a known public port (HTTPS) from the internet, and restrict SSH to a trusted IP range):

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Example secure SG
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 0.0.0.0/0
      - IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: 203.0.113.10/32
```

## Compliant Code Examples
```yaml
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Expose known ports to client host
        VpcId:
          Ref: myVPC
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 20
          ToPort: 23
          CidrIp: 0.0.0.0/0

```

```json
{
  "Resources": {
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Expose known port to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
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
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Expose unknown port to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 110,
            "ToPort": 119,
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
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Expose unknown port to client host
        VpcId:
          Ref: myVPC
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 23
          ToPort: 25
          CidrIp: 0.0.0.0/0

```