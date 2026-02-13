---
title: "VPC without Network Firewall"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/vpc_without_network_firewall"
  id: "3e293410-d5b8-411f-85fd-7d26294f20c9"
  display_name: "VPC without Network Firewall"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `3e293410-d5b8-411f-85fd-7d26294f20c9`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-networkfirewall-firewall.html#cfn-networkfirewall-firewall-vpcid)

### Description

VPCs should be associated with AWS Network Firewall to enable centralized traffic inspection and enforcement of network policies. This helps prevent lateral movement and detect or block malicious east–west and north–south traffic.

This rule checks CloudFormation for `AWS::EC2::VPC` resources that are not referenced by any `AWS::NetworkFirewall::Firewall` via the firewall's `Properties.VpcId`. The `VpcId` property in `AWS::NetworkFirewall::Firewall` must reference the VPC (for example, using `Ref` to the VPC logical ID). VPC resources without an associated `AWS::NetworkFirewall::Firewall` will be flagged.

Secure configuration example (Network Firewall referencing the VPC):

```yaml
MyVPC:
  Type: AWS::EC2::VPC
  Properties:
    CidrBlock: 10.0.0.0/16

MyNetworkFirewall:
  Type: AWS::NetworkFirewall::Firewall
  Properties:
    FirewallName: my-firewall
    VpcId:
      Ref: MyVPC
    SubnetMappings:
      - SubnetId: subnet-0123456789abcdef0
    FirewallPolicyArn: arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/example-policy
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
    myVPC1:
      Type: AWS::EC2::VPC
      Properties:
        CidrBlock: 10.0.0.0/16
        EnableDnsSupport: 'false'
        EnableDnsHostnames: 'false'
        InstanceTenancy: dedicated
    SampleFirewall:
      Type: AWS::NetworkFirewall::Firewall
      Properties:
        FirewallName: SampleFirewallName
        FirewallPolicyArn: !Ref SampleFirewallPolicy
        VpcId: !Ref myVPC1
        SubnetMappings:
          - SubnetId: !Ref SampleSubnet1
          - SubnetId: !Ref SampleSubnet2
        Description: Firewall description goes here

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "SampleFirewall": {
      "Properties": {
        "Description": "Firewall description goes here",
        "FirewallName": "SampleFirewallName",
        "FirewallPolicyArn": "SampleFirewallPolicy",
        "SubnetMappings": [
          {
            "SubnetId": "SampleSubnet1"
          },
          {
            "SubnetId": "SampleSubnet2"
          }
        ],
        "VpcId": "myVPC1"
      },
      "Type": "AWS::NetworkFirewall::Firewall"
    },
    "myVPC1": {
      "Properties": {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsHostnames": "false",
        "EnableDnsSupport": "false",
        "InstanceTenancy": "dedicated"
      },
      "Type": "AWS::EC2::VPC"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "SampleFirewall": {
      "Properties": {
        "Description": "Firewall description goes here",
        "FirewallName": "SampleFirewallName",
        "FirewallPolicyArn": "SampleFirewallPolicy",
        "SubnetMappings": [
          {
            "SubnetId": "SampleSubnet1"
          },
          {
            "SubnetId": "SampleSubnet2"
          }
        ],
        "VpcId": "myVPC"
      },
      "Type": "AWS::NetworkFirewall::Firewall"
    },
    "myVPC11": {
      "Properties": {
        "CidrBlock": "10.0.0.0/16",
        "EnableDnsHostnames": "false",
        "EnableDnsSupport": "false",
        "InstanceTenancy": "dedicated"
      },
      "Type": "AWS::EC2::VPC"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
    myVPC11:
      Type: AWS::EC2::VPC
      Properties:
        CidrBlock: 10.0.0.0/16
        EnableDnsSupport: 'false'
        EnableDnsHostnames: 'false'
        InstanceTenancy: dedicated
    SampleFirewall:
      Type: AWS::NetworkFirewall::Firewall
      Properties:
        FirewallName: SampleFirewallName
        FirewallPolicyArn: !Ref SampleFirewallPolicy
        VpcId: !Ref myVPC
        SubnetMappings:
          - SubnetId: !Ref SampleSubnet1
          - SubnetId: !Ref SampleSubnet2
        Description: Firewall description goes here

```