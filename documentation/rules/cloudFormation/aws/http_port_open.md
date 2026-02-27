---
title: "HTTP port open to internet"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/http_port_open"
  id: "ddfc4eaa-af23-409f-b96c-bf5c45dc4daa"
  display_name: "HTTP port open to internet"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ddfc4eaa-af23-409f-b96c-bf5c45dc4daa`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

Security groups should not allow HTTP (port `80`) ingress from the entire internet because it exposes web services to unauthenticated access and increases the attack surface for automated scanning and exploitation.
 
 In CloudFormation, inspect `AWS::EC2::SecurityGroup` resources' `SecurityGroupIngress` entries and ensure none have `CidrIp` = `0.0.0.0/0` or `CidrIpv6` = `::/0`, combined with `IpProtocol` set to `tcp`, `-1`, or `6`, and a port range that includes `80`. This rule flags ingress entries where `FromPort <= 80` and `ToPort >= 80`, indicating port `80` is open to the world.
 
 To remediate, restrict source CIDRs to trusted ranges, place services behind a load balancer or VPN, or require encrypted access (HTTPS/port `443`) instead of allowing global HTTP.

Secure configuration example (restrict to specific CIDR):

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
          FromPort: 80
          ToPort: 80
          CidrIp: 192.168.0.0/16

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
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "192.168.0.0/16"
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
        "GroupDescription": "Allow http to client host",
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
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0

```