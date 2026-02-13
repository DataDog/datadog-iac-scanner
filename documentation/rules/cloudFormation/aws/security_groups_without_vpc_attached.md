---
title: "Security groups without VPC attached"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/security_groups_without_vpc_attached"
  id: "493d9591-6249-47bf-8dc0-5c10161cc558"
  display_name: "Security groups without VPC attached"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `493d9591-6249-47bf-8dc0-5c10161cc558`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html)

### Description

 Security groups must be associated with a specific VPC to ensure network isolation and to allow enforcement of VPC-level controls. A security group without a `VpcId` may end up outside the intended VPC (or require EC2-Classic), which prevents proper subnet scoping, VPC flow logging, and other VPC security controls and can lead to unintended exposure.

For `AWS::EC2::SecurityGroup` resources, `Properties.VpcId` must be defined (for example, `!Ref MyVPC` or an explicit VPC ID). This rule flags security groups where `Properties.VpcId` is undefined and the group is not the default group (`GroupName != "default"`).

Secure example with `VpcId` set:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Allow HTTP
    VpcId: !Ref MyVPC
    SecurityGroupIngress:
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
      GroupName: My Group Name
      GroupDescription: Enable SSH access via port 22
      VpcId:
        Ref: myVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: '22'
          ToPort: '22'
          CidrIp: 0.0.0.0/0
```

```json
{
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
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22",
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "GroupName": "My Group Name",
        "GroupDescription": "Enable SSH access via port 22",
        "VpcId": {
          "Ref": "myVPC"
        }
      }
    }
  },
  "Parameters": {
    "KeyName": {
      "Description": "The EC2 Key Pair to allow SSH access to the instance",
      "Type": "AWS::EC2::KeyPair::KeyName"
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
      "Properties": {
        "SecurityGroups": [
          "InstanceSecurityGroup",
          "MyExistingSecurityGroup"
        ],
        "KeyName": "KeyName",
        "ImageId": "ami-7a11e213"
      },
      "Type": "AWS::EC2::Instance"
    },
    "InstanceSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupName": "My Group Name",
        "GroupDescription": "Enable SSH access via port 22",
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22",
            "CidrIp": "0.0.0.0/0"
          }
        ]
      }
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
      GroupName: My Group Name
      GroupDescription: Enable SSH access via port 22
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: '22'
          ToPort: '22'
          CidrIp: 0.0.0.0/0
```