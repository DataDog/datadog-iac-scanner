---
title: "Security groups allows unrestricted outbound traffic"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/security_groups_allows_unrestricted_outbound_traffic"
  id: "66f2d8f9-a911-4ced-ae27-34f09690bb2c"
  display_name: "Security groups allows unrestricted outbound traffic"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `66f2d8f9-a911-4ced-ae27-34f09690bb2c`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

 Security groups must not allow unrestricted outbound traffic by combining `IpProtocol: "ALL"` with `CidrIp: "0.0.0.0/0"`. This permits any protocol to any internet destination and can enable data exfiltration, malware callbacks, and make detection or containment harder.

In CloudFormation, check `AWS::EC2::SecurityGroup` resources and flag any `SecurityGroupEgress` entry where `IpProtocol` is `ALL` and `CidrIp` is `0.0.0.0/0`. Entries that include `IpProtocol: "ALL"` together with `CidrIp: "0.0.0.0/0"` will be flagged. Instead, define explicit protocols and ports and restrict destination CIDR blocks to the minimum required. If broad internet egress is needed, prefer specific ports (for example, TCP/`443`) or centralize outbound access through NAT gateways, proxies, or VPC endpoints.

Secure configuration example with explicit ports and restricted destinations:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Example secure egress rules
    VpcId: vpc-123456
    SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 0.0.0.0/0
      - IpProtocol: tcp
        FromPort: 80
        ToPort: 80
        CidrIp: 10.0.0.0/16
```


## Compliant Code Examples
```yaml
Parameters:
  KeyName:
    Description: The EC2 Key Pair to allow SSH access to the instance
    Type: 'AWS::EC2::KeyPair::KeyName'
Resources:
  Ec2Instance:
    Type: 'AWS::EC2::Instance'
    Properties:
      SecurityGroups:
        - !Ref InstanceSecurityGroup
        - MyExistingSecurityGroup
      KeyName: !Ref KeyName
      ImageId: ami-7a11e213
  InstanceSecurityGroup:
    Type: 'AWS::EC2::SecurityGroup'
    Properties:
      GroupDescription: Enable SSH access via port 22
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: '22'
          ToPort: '22'
          CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: '22'
          ToPort: '22'
          CidrIp: 0.0.0.0/0
```

```json
{
  "Parameters": {
    "KeyName": {
      "Description": "The EC2 Key Pair to allow SSH access to the instance",
      "Type": "AWS::EC2::KeyPair::KeyName"
    }
  },
  "Resources": {
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "SecurityGroups": [
          "InstanceSecurityGroup",
          "MyExistingSecurityGroup"
        ],
        "KeyName": "KeyName",
        "ImageId": "ami-7a11e213"
      }
    },
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Enable SSH access via port 22",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22",
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22"
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
  "Parameters": {
    "KeyName": {
      "Description": "The EC2 Key Pair to allow SSH access to the instance",
      "Type": "AWS::EC2::KeyPair::KeyName"
    }
  },
  "Resources": {
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-7a11e213",
        "SecurityGroups": [
          "InstanceSecurityGroup",
          "MyExistingSecurityGroup"
        ],
        "KeyName": "KeyName"
      }
    },
    "InstanceSecurityGroup": {
      "Properties": {
        "SecurityGroupIngress": [
          {
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22"
          }
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "ALL",
            "FromPort": "22",
            "ToPort": "22",
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "GroupDescription": "Enable SSH access via port 22"
      },
      "Type": "AWS::EC2::SecurityGroup"
    }
  }
}

```

```yaml
Parameters:
  KeyName:
    Description: The EC2 Key Pair to allow SSH access to the instance
    Type: 'AWS::EC2::KeyPair::KeyName'
Resources:
  Ec2Instance:
    Type: 'AWS::EC2::Instance'
    Properties:
      SecurityGroups:
        - !Ref InstanceSecurityGroup
        - MyExistingSecurityGroup
      KeyName: !Ref KeyName
      ImageId: ami-7a11e213
  InstanceSecurityGroup:
    Type: 'AWS::EC2::SecurityGroup'
    Properties:
      GroupDescription: Enable SSH access via port 22
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: '22'
          ToPort: '22'
          CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
        - IpProtocol: ALL
          FromPort: '22'
          ToPort: '22'
          CidrIp: 0.0.0.0/0
```