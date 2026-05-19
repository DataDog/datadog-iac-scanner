---
title: "EC2 instance subnet has public IP mapping on launch"
group_id: "CloudFormation / AWS"
meta:
  name: ""aws/ec2_instance_subnet_has_public_ip_mapping_on_launch""
  id: "cloudformation-aws-ec2-instance-subnet-has-public-ip-mapping-on-launch"
  display_name: "EC2 instance subnet has public IP mapping on launch"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}cloudformation-aws-ec2-instance-subnet-has-public-ip-mapping-on-launch{{< /copyable-code >}}

**Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-subnet.html#cfn-ec2-subnet-mappubliciponlaunch)

### Description

Subnets must not automatically assign public IPv4 addresses to instances because automatic public IP assignment exposes instances directly to the internet and increases the risk of unauthorized access and data exposure. For CloudFormation, the `AWS::EC2::Subnet` resource's `Properties.MapPublicIpOnLaunch` property must be defined and set to `false`. Resources with `MapPublicIpOnLaunch` set to `true` will be flagged. For private subnets, explicitly set this property to `false` and use NAT gateways, bastion hosts, or load balancers to provide controlled outbound or inbound access.

Secure configuration example:

```yaml
MyPrivateSubnet:
  Type: AWS::EC2::Subnet
  Properties:
    VpcId: !Ref MyVPC
    CidrBlock: 10.0.1.0/24
    MapPublicIpOnLaunch: false
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
   mySubnet:
    Type: AWS::EC2::Subnet
    Properties:
      MapPublicIpOnLaunch: false
      VpcId: myVPC
      CidrBlock: 10.0.0.0/24
      AvailabilityZone: "us-east-1a"
      Tags:
      - Key: foo
        Value: bar

```

```json
{
  "Resources": {
    "mySubnet": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "Tags": [
          {
            "Key": "foo",
            "Value": "bar"
          }
        ],
        "MapPublicIpOnLaunch": false,
        "VpcId": "myVPC",
        "CidrBlock": "10.0.0.0/24",
        "AvailabilityZone": "us-east-1a"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A sample template",
  "Resources": {
    "mySubnet": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "MapPublicIpOnLaunch": true,
        "VpcId": "myVPC",
        "CidrBlock": "10.0.0.0/24",
        "AvailabilityZone": "us-east-1a",
        "Tags": [
          {
            "Key": "foo",
            "Value": "bar"
          }
        ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
   mySubnet:
    Type: AWS::EC2::Subnet
    Properties:
      MapPublicIpOnLaunch: true
      VpcId: myVPC
      CidrBlock: 10.0.0.0/24
      AvailabilityZone: "us-east-1a"
      Tags:
      - Key: foo
        Value: bar

```