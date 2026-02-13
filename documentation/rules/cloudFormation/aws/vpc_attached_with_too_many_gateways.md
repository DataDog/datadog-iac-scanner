---
title: "VPC attached with too many gateways"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/vpc_attached_with_too_many_gateways"
  id: "97e94d17-e2c7-4109-a53b-6536ac1bb64e"
  display_name: "VPC attached with too many gateways"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `97e94d17-e2c7-4109-a53b-6536ac1bb64e`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html)

### Description

 Attaching an excessive number of gateways to a single VPC increases the attack surface and may indicate misconfiguration or exceed AWS service limits. Exceeding service limits can cause routing problems or service disruption.

This rule checks `AWS::EC2::VPC` resources and counts `AWS::EC2::VPCGatewayAttachment` resources whose `Properties.VpcId` refers to that VPC. The count must not be greater than `3`. Resources with more than three gateway attachments referencing the VPC will be flagged. `VpcId` may be specified as a literal value or a `Ref`.

Secure configuration example showing a single gateway attachment:

```yaml
MyVPC:
  Type: AWS::EC2::VPC
  Properties:
    CidrBlock: 10.0.0.0/16

MyInternetGateway:
  Type: AWS::EC2::InternetGateway

MyVPCGatewayAttachment:
  Type: AWS::EC2::VPCGatewayAttachment
  Properties:
    VpcId: !Ref MyVPC
    InternetGatewayId: !Ref MyInternetGateway
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
    AttachVpnGateway:
      Type: AWS::EC2::VPCGatewayAttachment
      Properties:
        VpcId:
           Ref: myVPC_2
        VpnGatewayId:
           Ref: myVPNGateway
    AttachVpnGateway2:
      Type: AWS::EC2::VPCGatewayAttachment
      Properties:
        VpcId:
           Ref: myVPC_2
        VpnGatewayId:
           Ref: myVPNGateway2
    AttachVpnGateway3:
      Type: AWS::EC2::VPCGatewayAttachment
      Properties:
        VpcId:
           Ref: myVPC_2
        VpnGatewayId:
           Ref: myVPNGateway3

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
    "AttachVpnGateway": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC_2"
        },
        "VpnGatewayId": {
          "Ref": "myVPNGateway"
        }
      }
    },
    "AttachVpnGateway2": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC_2"
        },
        "VpnGatewayId": {
          "Ref": "myVPNGateway2"
        }
      }
    },
    "AttachVpnGateway3": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC_2"
        },
        "VpnGatewayId": {
          "Ref": "myVPNGateway3"
        }
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
    "AttachVpnGateway4": {
      "Properties": {
        "VpcId": {
          "Ref": "myVPC"
        },
        "VpnGatewayId": {
          "Ref": "myVPNGateway4"
        }
      },
      "Type": "AWS::EC2::VPCGatewayAttachment"
    },
    "myVPC": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "EnableDnsHostnames": "false",
        "InstanceTenancy": "dedicated",
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsSupport": "false"
      }
    },
    "AttachVpnGateway": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC"
        },
        "VpnGatewayId": {
          "Ref": "myVPNGateway"
        }
      }
    },
    "AttachVpnGateway2": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC"
        },
        "VpnGatewayId": {
          "Ref": "myVPNGateway2"
        }
      }
    },
    "AttachVpnGateway3": {
      "Type": "AWS::EC2::VPCGatewayAttachment",
      "Properties": {
        "VpcId": {
          "Ref": "myVPC"
        },
        "VpnGatewayId": {
          "Ref": "myVPNGateway3"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
    myVPC:
      Type: AWS::EC2::VPC
      Properties:
        CidrBlock: 10.0.0.0/16
        EnableDnsSupport: 'false'
        EnableDnsHostnames: 'false'
        InstanceTenancy: dedicated
    AttachVpnGateway:
      Type: AWS::EC2::VPCGatewayAttachment
      Properties:
        VpcId:
           Ref: myVPC
        VpnGatewayId:
           Ref: myVPNGateway
    AttachVpnGateway2:
      Type: AWS::EC2::VPCGatewayAttachment
      Properties:
        VpcId:
           Ref: myVPC
        VpnGatewayId:
           Ref: myVPNGateway2
    AttachVpnGateway3:
      Type: AWS::EC2::VPCGatewayAttachment
      Properties:
        VpcId:
           Ref: myVPC
        VpnGatewayId:
           Ref: myVPNGateway3
    AttachVpnGateway4:
      Type: AWS::EC2::VPCGatewayAttachment
      Properties:
        VpcId:
           Ref: myVPC
        VpnGatewayId:
           Ref: myVPNGateway4

```