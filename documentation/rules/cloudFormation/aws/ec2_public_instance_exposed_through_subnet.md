---
title: "EC2 public instance exposed through subnet"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/ec2_public_instance_exposed_through_subnet"
  id: "c44c95fc-ae92-4bb8-bdf8-bb9bc412004a"
  display_name: "EC2 public instance exposed through subnet"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `c44c95fc-ae92-4bb8-bdf8-bb9bc412004a`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-route.html)

### Description

 EC2 instances should not be assigned public IP addresses in subnets that have a default route to the internet, because doing so exposes those instances to unrestricted inbound and outbound traffic and increases the risk of unauthorized access, exploitation, and data exfiltration. This rule checks `AWS::EC2::Instance` resources' `NetworkInterfaces[*].AssociatePublicIpAddress` property. It flags instances where this is `true` and the subnet referenced by `NetworkInterfaces[*].SubnetId` is associated (via `AWS::EC2::SubnetRouteTableAssociation`) with a route table that contains an `AWS::EC2::Route` having `DestinationCidrBlock` set to `0.0.0.0/0` or `DestinationIpv6CidrBlock` set to `::/0`.
 
 To remediate, avoid assigning public IPs to instances in those subnets, place workloads in private subnets that use a NAT gateway for outbound access, or remove/restrict the default `0.0.0.0/0` or `::/0` route from the subnet's route table.

Secure configuration example (instance in private subnet):

```yaml
MyInstance:
  Type: AWS::EC2::Instance
  Properties:
    ImageId: ami-0abcdef1234567890
    InstanceType: t3.micro
    NetworkInterfaces:
      - AssociatePublicIpAddress: false
        SubnetId: !Ref MyPrivateSubnet
        DeviceIndex: 0
```


## Compliant Code Examples
```yaml
Resources:
  myVPC_1:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsSupport: false
      EnableDnsHostnames: false
      InstanceTenancy: dedicated
  InternetGateway:
    Type: AWS::EC2::InternetGateway
  VPCGatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      InternetGatewayId: !Ref InternetGateway
      VpcId: !Ref myVPC_1
  myRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref myVPC_1
  myRoute:
      Type: AWS::EC2::Route
      DependsOn: VPCGatewayAttachment
      Properties:
        RouteTableId: !Ref myRouteTable
        DestinationCidrBlock: 0.0.0.0/0
        DestinationIpv6CidrBlock: ::/0
        GatewayId: !Ref InternetGateway
  mySubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref myVPC_1
      CidrBlock: 10.0.0.0/24
      AvailabilityZone: "us-east-1a"
  mySubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref mySubnet
      RouteTableId: !Ref myRouteTable
  Ec2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0ff8a91507f77f867
      KeyName: !Ref Keyname
      NetworkInterfaces:
        - AssociatePublicIpAddress: false
          DeviceIndex: "0"
          SubnetId: !Ref mySubnet

```

```json
{
  "Resources": {
    "myVPC_3": {
      "Properties": {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsSupport": false,
        "EnableDnsHostnames": false,
        "InstanceTenancy": "dedicated"
      },
      "Type": "AWS::EC2::VPC"
    },
    "InternetGateway_2": {
      "Type": "AWS::EC2::InternetGateway"
    },
    "VPCGatewayAttachment_2": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": "myVPC_3",
        "InternetGatewayId": "InternetGateway_2"
      }
    },
    "myRouteTable_2": {
      "Type": "AWS::EC2::RouteTable",
      "Properties": {
        "VpcId": "myVPC_3"
      }
    },
    "mySubnet_2": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "VpcId": "myVPC_3",
        "CidrBlock": "10.0.0.0/24",
        "AvailabilityZone": "us-east-1a"
      }
    },
    "mySubnetRouteTableAssociation_2": {
      "Type": "AWS::EC2::SubnetRouteTableAssociation",
      "Properties": {
        "SubnetId": "mySubnet_2",
        "RouteTableId": "myRouteTable_2"
      }
    },
    "Ec2Instance_2": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "NetworkInterfaces": [
          {
            "AssociatePublicIpAddress": true,
            "DeviceIndex": "0",
            "SubnetId": "mySubnet_2"
          }
        ],
        "ImageId": "ami-0ff8a91507f77f867",
        "KeyName": "Keyname"
      }
    }
  }
}

```

```yaml

Resources:
  myVPC_3:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsSupport: false
      EnableDnsHostnames: false
      InstanceTenancy: dedicated
  InternetGateway_2:
    Type: AWS::EC2::InternetGateway
  VPCGatewayAttachment_2:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      InternetGatewayId: !Ref InternetGateway_2
      VpcId: !Ref myVPC_3
  myRouteTable_2:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref myVPC_3
  mySubnet_2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref myVPC_3
      CidrBlock: 10.0.0.0/24
      AvailabilityZone: "us-east-1a"
  mySubnetRouteTableAssociation_2:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref mySubnet_2
      RouteTableId: !Ref myRouteTable_2
  Ec2Instance_2:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0ff8a91507f77f867
      KeyName: !Ref Keyname
      NetworkInterfaces:
        - AssociatePublicIpAddress: true
          DeviceIndex: "0"
          SubnetId: !Ref mySubnet_2

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "mySubnet": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "AvailabilityZone": "us-east-1a",
        "VpcId": "myVPC_1",
        "CidrBlock": "10.0.0.0/24"
      }
    },
    "mySubnetRouteTableAssociation": {
      "Properties": {
        "SubnetId": "mySubnet",
        "RouteTableId": "myRouteTable"
      },
      "Type": "AWS::EC2::SubnetRouteTableAssociation"
    },
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-0ff8a91507f77f867",
        "KeyName": "Keyname",
        "NetworkInterfaces": [
          {
            "SubnetId": "mySubnet",
            "AssociatePublicIpAddress": true,
            "DeviceIndex": "0"
          }
        ]
      }
    },
    "myVPC_1": {
      "Properties": {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsSupport": false,
        "EnableDnsHostnames": false,
        "InstanceTenancy": "dedicated"
      },
      "Type": "AWS::EC2::VPC"
    },
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway"
    },
    "VPCGatewayAttachment": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "InternetGatewayId": "InternetGateway",
        "VpcId": "myVPC_1"
      }
    },
    "myRouteTable": {
      "Type": "AWS::EC2::RouteTable",
      "Properties": {
        "VpcId": "myVPC_1"
      }
    },
    "myRoute": {
      "Type": "AWS::EC2::Route",
      "DependsOn": "VPCGatewayAttachment",
      "Properties": {
        "RouteTableId": "myRouteTable",
        "DestinationCidrBlock": "0.0.0.0/0",
        "DestinationIpv6CidrBlock": "::/0",
        "GatewayId": "InternetGateway"
      }
    }
  }
}

```

```yaml
Resources:
  myVPC_1:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsSupport: false
      EnableDnsHostnames: false
      InstanceTenancy: dedicated
  InternetGateway:
    Type: AWS::EC2::InternetGateway
  VPCGatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      InternetGatewayId: !Ref InternetGateway
      VpcId: !Ref myVPC_1
  myRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref myVPC_1
  myRoute:
      Type: AWS::EC2::Route
      DependsOn: VPCGatewayAttachment
      Properties:
        RouteTableId: !Ref myRouteTable
        DestinationCidrBlock: 0.0.0.0/0
        DestinationIpv6CidrBlock: ::/0
        GatewayId: !Ref InternetGateway
  mySubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref myVPC_1
      CidrBlock: 10.0.0.0/24
      AvailabilityZone: "us-east-1a"
  mySubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref mySubnet
      RouteTableId: !Ref myRouteTable
  Ec2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0ff8a91507f77f867
      KeyName: !Ref Keyname
      NetworkInterfaces:
        - AssociatePublicIpAddress: true
          DeviceIndex: "0"
          SubnetId: !Ref mySubnet

```