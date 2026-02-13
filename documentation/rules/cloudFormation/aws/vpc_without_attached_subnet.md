---
title: "VPC without attached subnet"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/vpc_without_attached_subnet"
  id: "3b3b4411-ad1f-40e7-b257-a78a6bb9673a"
  display_name: "VPC without attached subnet"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `3b3b4411-ad1f-40e7-b257-a78a6bb9673a`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html)

### Description

VPCs without any attached subnets can indicate unused or orphaned networks that increase the attack surface and hinder enforcement of network segmentation and security controls.

In CloudFormation, every `AWS::EC2::VPC` resource should be referenced by at least one `AWS::EC2::Subnet` via the subnet's `Properties.VpcId` (for example, a `Ref` to the VPC logical ID). This rule flags `AWS::EC2::VPC` resources defined in the same template that have no `AWS::EC2::Subnet` resources referencing them. If subnets are created in another stack or outside the template, include the subnet resources in the same template or ensure the VPC/subnet relationship is expressed in CloudFormation to avoid false positives.

Secure configuration example:

```yaml
MyVPC:
  Type: AWS::EC2::VPC
  Properties:
    CidrBlock: 10.0.0.0/16
    EnableDnsSupport: true
    EnableDnsHostnames: true

MySubnet:
  Type: AWS::EC2::Subnet
  Properties:
    VpcId: !Ref MyVPC
    CidrBlock: 10.0.1.0/24
    AvailabilityZone: us-east-1a
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
    myVPC_2:
      Type: AWS::EC2::VPC
      Properties:
        CidrBlock: 10.0.0.0/16
        EnableDnsSupport: 'false'
        EnableDnsHostnames: 'false'
        InstanceTenancy: dedicated
    mySubnet:
      Type: AWS::EC2::Subnet
      Properties:
        VpcId:
            Ref: myVPC_2
        CidrBlock: 10.0.0.0/24
        AvailabilityZone: "us-east-1a"

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "myVPC_2": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsSupport": "false",
        "EnableDnsHostnames": "false",
        "InstanceTenancy": "dedicated"
      }
    },
    "mySubnet": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC_2"
        },
        "CidrBlock": "10.0.0.0/24",
        "AvailabilityZone": "us-east-1a"
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
    "myVPC_1": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "InstanceTenancy": "dedicated",
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsSupport": "false",
        "EnableDnsHostnames": "false"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
    myVPC_1:
      Type: AWS::EC2::VPC
      Properties:
        CidrBlock: 10.0.0.0/16
        EnableDnsSupport: 'false'
        EnableDnsHostnames: 'false'
        InstanceTenancy: dedicated

```