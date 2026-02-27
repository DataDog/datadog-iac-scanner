---
title: "GameLift fleet EC2 inbound permissions with port range"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/gamelift_fleet_ec2_inbound_permissions_with_port_range"
  id: "43356255-495d-4148-ad8d-f6af5eac09dd"
  display_name: "GameLift fleet EC2 inbound permissions with port range"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `43356255-495d-4148-ad8d-f6af5eac09dd`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-gamelift-fleet.html)

### Description

Opening port ranges for GameLift fleet instances increases the attack surface by exposing multiple ports instead of a single intended port. This can allow additional network-based attacks and makes it harder to reason about allowed traffic.
 
 For `AWS::GameLift::Fleet` resources, each entry in the `Properties.EC2InboundPermissions` array must set `FromPort` and `ToPort` to the same numeric value so only a single port is opened. Resources with `EC2InboundPermissions` entries where `FromPort` is not equal to `ToPort` will be flagged. Ensure both properties are defined and equal for every entry.

Secure configuration example:

```yaml
MyGameLiftFleet:
  Type: AWS::GameLift::Fleet
  Properties:
    EC2InboundPermissions:
      - FromPort: 3478
        ToPort: 3478
        IpRange: 0.0.0.0/0
        Protocol: UDP
```

## Compliant Code Examples
```yaml
Resources:
  FleetResource2:
    Type: AWS::GameLift::Fleet
    Properties:
      BuildId: !Ref BuildResource
      CertificateConfiguration:
        CertificateType: DISABLED
      Description: Description of my Game Fleet
      DesiredEc2Instances: 1
      EC2InboundPermissions:
        - FromPort: '1234'
          ToPort: '1234'
          IpRange: 0.0.0.0/24
          Protocol: TCP
        - FromPort: '1356'
          ToPort: '1356'
          IpRange: 192.168.0.0/24
          Protocol: UDP

```

```json
{
  "Resources": {
    "FleetResource2": {
      "Type": "AWS::GameLift::Fleet",
      "Properties": {
        "CertificateConfiguration": {
          "CertificateType": "DISABLED"
        },
        "Description": "Description of my Game Fleet",
        "DesiredEc2Instances": 1,
        "EC2InboundPermissions": [
          {
            "FromPort": "1234",
            "ToPort": "1234",
            "IpRange": "0.0.0.0/24",
            "Protocol": "TCP"
          },
          {
            "ToPort": "1356",
            "IpRange": "192.168.0.0/24",
            "Protocol": "UDP",
            "FromPort": "1356"
          }
        ],
        "BuildId": "BuildResource"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "FleetResource1": {
      "Type": "AWS::GameLift::Fleet",
      "Properties": {
        "EC2InboundPermissions": [
          {
            "FromPort": "1234",
            "ToPort": "134",
            "IpRange": "0.0.0.0/24",
            "Protocol": "TCP"
          },
          {
            "FromPort": 1356,
            "ToPort": 1578,
            "IpRange": "192.168.0.0/24",
            "Protocol": "UDP"
          }
        ],
        "BuildId": "BuildResource",
        "CertificateConfiguration": {
          "CertificateType": "DISABLED"
        },
        "Description": "Description of my Game Fleet1",
        "DesiredEc2Instances": 1
      }
    },
    "FleetResource3": {
      "Type": "AWS::GameLift::Fleet",
      "Properties": {
        "BuildId": "BuildResource",
        "CertificateConfiguration": {
          "CertificateType": "DISABLED"
        },
        "Description": "Description of my Game Fleet3",
        "DesiredEc2Instances": 1,
        "EC2InboundPermissions": [
          {
            "FromPort": 1234,
            "ToPort": "134",
            "IpRange": "0.0.0.0/24",
            "Protocol": "TCP"
          },
          {
            "FromPort": "1356",
            "ToPort": 1578,
            "IpRange": "192.168.0.0/24",
            "Protocol": "UDP"
          }
        ]
      }
    }
  }
}

```

```yaml
Resources:
  FleetResource1:
    Type: AWS::GameLift::Fleet
    Properties:
      BuildId: !Ref BuildResource
      CertificateConfiguration:
        CertificateType: DISABLED
      Description: Description of my Game Fleet1
      DesiredEc2Instances: 1
      EC2InboundPermissions:
        - FromPort: '1234'
          ToPort: '134'
          IpRange: 0.0.0.0/24
          Protocol: TCP
        - FromPort: 1356
          ToPort: 1578
          IpRange: 192.168.0.0/24
          Protocol: UDP
  FleetResource3:
    Type: AWS::GameLift::Fleet
    Properties:
      BuildId: !Ref BuildResource
      CertificateConfiguration:
        CertificateType: DISABLED
      Description: Description of my Game Fleet3
      DesiredEc2Instances: 1
      EC2InboundPermissions:
        - FromPort: 1234
          ToPort: '134'
          IpRange: 0.0.0.0/24
          Protocol: TCP
        - FromPort: '1356'
          ToPort: 1578
          IpRange: 192.168.0.0/24
          Protocol: UDP

```