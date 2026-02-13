---
title: "Remote Desktop port open to the internet"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/remote_desktop_port_open_to_internet"
  id: "c9846969-d066-431f-9b34-8c4abafe422a"
  display_name: "Remote Desktop port open to the internet"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `c9846969-d066-431f-9b34-8c4abafe422a`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

Opening the Remote Desktop service (TCP port `3389`) to the public internet exposes Windows hosts to automated scanning and brute‑force attacks and enables unauthorized remote access that can lead to credential compromise and lateral movement. In AWS CloudFormation, inspect `AWS::EC2::SecurityGroup` resources' `Properties.SecurityGroupIngress` entries and flag any ingress where `CidrIp` is `0.0.0.0/0` or `CidrIpv6` is `::/0`, `IpProtocol` is TCP (`tcp`, `-1`, or `6`), and the port range includes `3389` (`FromPort` <= `3389` and `ToPort` >= `3389`). Replace global access with specific trusted CIDR ranges or remove the rule. Provide remote access via a bastion host, VPN, or AWS Systems Manager Session Manager instead of exposing RDP directly. 
 
 Secure example restricting RDP to a single trusted IP:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Allow RDP from trusted admin network only
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 3389
        ToPort: 3389
        CidrIp: 203.0.113.4/32
```

## Compliant Code Examples
```yaml
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
        GroupDescription: Allow rdp to client host
        VpcId:
          Ref: myVPC
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 192.168.0.0/16

```

```json
{
  "Resources": {
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow rdp to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
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
        "GroupDescription": "Allow rdp to client host",
        "VpcId": {
          "Ref": "myVPC"
        },
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
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
        GroupDescription: Allow rdp to client host
        VpcId:
          Ref: myVPC
        SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0

```