---
title: "Route table with default routing"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/routertable_with_default_routing"
  id: "4f0908b9-eb66-433f-9145-134274e1e944"
  display_name: "Route table with default routing"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `4f0908b9-eb66-433f-9145-134274e1e944`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-route-table.html)

### Description

Default routes that use IPv4 `0.0.0.0/0` or IPv6 `::/0` can expose subnets and instances to the public internet. This increases the risk of unauthorized access, data exfiltration, and lateral movement.

In CloudFormation, inspect `AWS::EC2::Route` resources. If `DestinationCidrBlock` equals `0.0.0.0/0` or `DestinationIpv6CidrBlock` equals `::/0`, the route must explicitly target a NAT gateway so outbound traffic from private subnets is proxied rather than directly exposed. Ensure the `NatGatewayId` property is defined on routes that provide internet-bound access. Resources missing `NatGatewayId`, or with a default destination but no NAT gateway, will be flagged.

Secure configuration example (route to a NAT gateway):

```yaml
PrivateRoute:
  Type: AWS::EC2::Route
  Properties:
    RouteTableId: !Ref PrivateRouteTable
    DestinationCidrBlock: 0.0.0.0/0
    NatGatewayId: !Ref MyNatGateway
```

## Compliant Code Examples
```yaml
Resources:
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.1.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
          - Key: Name
            Value:  !Join ['', [!Ref "AWS::StackName", "-VPC" ]]
  InternetGateway:
    Type: AWS::EC2::InternetGateway
    DependsOn: VPC
  AttachGateway:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref VPC
      InternetGatewayId: !Ref InternetGateway
  PublicSubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.1.10.0/24
      AvailabilityZone: !Select [ 0, !GetAZs ]    # Obtenha o primeiro AZ na lista
      Tags:
          - Key: Name
            Value: !Sub ${AWS::StackName}-Public-A
  Ec2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId:
       Fn::FindInMap:
             - "RegionMap"
             - Ref: "AWS::Region"
             - "AMI"
      KeyName:
       Ref: "KeyName"
      NetworkInterfaces:
        - AssociatePublicIpAddress: true
          DeviceIndex: "0"
          SubnetId: !Ref PublicSubnetA
  PublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref VPC
      Tags:
      - Key: Name
        Value: Public
  PublicRoute1:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 172.16.0.0/24
      NatGatewayId: !Ref InternetGateway

```

```json
{
  "Resources": {
    "VPC": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "CidrBlock": "10.1.0.0/16",
        "EnableDnsSupport": true,
        "EnableDnsHostnames": true,
        "Tags": [
          {
            "Key": "Name",
            "Value": [
              "",
              [
                "AWS::StackName",
                "-VPC"
              ]
            ]
          }
        ]
      }
    },
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway",
      "DependsOn": "VPC"
    },
    "AttachGateway": {
      "Properties": {
        "VpcId": "VPC",
        "InternetGatewayId": "InternetGateway"
      },
      "Type": "AWS::EC2::VPCGatewayAttachment"
    },
    "PublicSubnetA": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "VpcId": "VPC",
        "CidrBlock": "10.1.10.0/24",
        "AvailabilityZone": [
          0,
          ""
        ],
        "Tags": [
          {
            "Value": "${AWS::StackName}-Public-A",
            "Key": "Name"
          }
        ]
      }
    },
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": {
          "Fn::FindInMap": [
            "RegionMap",
            {
              "Ref": "AWS::Region"
            },
            "AMI"
          ]
        },
        "KeyName": {
          "Ref": "KeyName"
        },
        "NetworkInterfaces": [
          {
            "AssociatePublicIpAddress": true,
            "DeviceIndex": "0",
            "SubnetId": "PublicSubnetA"
          }
        ]
      }
    },
    "PublicRouteTable": {
      "Type": "AWS::EC2::RouteTable",
      "Properties": {
        "VpcId": "VPC",
        "Tags": [
          {
            "Key": "Name",
            "Value": "Public"
          }
        ]
      }
    },
    "PublicRoute1": {
      "Type": "AWS::EC2::Route",
      "DependsOn": "AttachGateway",
      "Properties": {
        "RouteTableId": "PublicRouteTable",
        "DestinationCidrBlock": "172.16.0.0/24",
        "NatGatewayId": "InternetGateway"
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "InternetGateway": {
      "Type": "AWS::EC2::InternetGateway",
      "DependsOn": "VPC"
    },
    "Ec2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": {
          "Fn::FindInMap": [
            "RegionMap",
            {
              "Ref": "AWS::Region"
            },
            "AMI"
          ]
        },
        "KeyName": {
          "Ref": "KeyName"
        },
        "NetworkInterfaces": [
          {
            "AssociatePublicIpAddress": true,
            "DeviceIndex": "0",
            "SubnetId": "PublicSubnetA"
          }
        ]
      }
    },
    "PublicRoute1": {
      "Type": "AWS::EC2::Route",
      "DependsOn": "AttachGateway",
      "Properties": {
        "NatGatewayId": "id",
        "RouteTableId": "PublicRouteTable",
        "DestinationCidrBlock": "0.0.0.0/0"
      }
    },
    "PublicRoute3": {
      "Type": "AWS::EC2::Route",
      "DependsOn": "AttachGateway",
      "Properties": {
        "RouteTableId": "PublicRouteTable",
        "DestinationCidrBlock": "10.1.10.0/24"
      }
    },
    "VPC": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "Tags": [
          {
            "Key": "Name",
            "Value": [
              "",
              [
                "AWS::StackName",
                "-VPC"
              ]
            ]
          }
        ],
        "CidrBlock": "10.1.0.0/16",
        "EnableDnsSupport": true,
        "EnableDnsHostnames": true
      }
    },
    "AttachGateway": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": "VPC",
        "InternetGatewayId": "InternetGateway"
      }
    },
    "PublicSubnetA": {
      "Type": "AWS::EC2::Subnet",
      "Properties": {
        "VpcId": "VPC",
        "CidrBlock": "10.1.10.0/24",
        "AvailabilityZone": [
          0,
          ""
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "${AWS::StackName}-Public-A"
          }
        ]
      }
    },
    "PublicRouteTable": {
      "Type": "AWS::EC2::RouteTable",
      "Properties": {
        "VpcId": "VPC",
        "Tags": [
          {
            "Key": "Name",
            "Value": "Public"
          }
        ]
      }
    },
    "PublicRoute2": {
      "DependsOn": "AttachGateway",
      "Properties": {
        "RouteTableId": "PublicRouteTable",
        "DestinationIpv6CidrBlock": "::/0",
        "NatGatewayId": "id"
      },
      "Type": "AWS::EC2::Route"
    }
  }
}

```

```yaml
Resources:
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.1.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
          - Key: Name
            Value:  !Join ['', [!Ref "AWS::StackName", "-VPC" ]]
  InternetGateway:
    Type: AWS::EC2::InternetGateway
    DependsOn: VPC
  AttachGateway:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref VPC
      InternetGatewayId: !Ref InternetGateway
  PublicSubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: 10.1.10.0/24
      AvailabilityZone: !Select [ 0, !GetAZs ]    # Obtenha o primeiro AZ na lista
      Tags:
          - Key: Name
            Value: !Sub ${AWS::StackName}-Public-A
  Ec2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId:
       Fn::FindInMap:
            - "RegionMap"
            - Ref: "AWS::Region"
            - "AMI"
      KeyName:
       Ref: "KeyName"
      NetworkInterfaces:
        -   AssociatePublicIpAddress: true
            DeviceIndex: "0"
            SubnetId: !Ref PublicSubnetA
  PublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref VPC
      Tags:
      - Key: Name
        Value: Public
  PublicRoute1:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      NatGatewayId: id
  PublicRoute2:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationIpv6CidrBlock: ::/0
      NatGatewayId: id
  PublicRoute3:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: 10.1.10.0/24

```