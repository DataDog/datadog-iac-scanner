---
title: "ELB with security group without inbound rules"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elb_with_security_group_without_inbound_rules"
  id: "e200a6f3-c589-49ec-9143-7421d4a2c845"
  display_name: "ELB with security group without inbound rules"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `e200a6f3-c589-49ec-9143-7421d4a2c845`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-securitygroupingress)

### Description

Load balancers must not reference security groups that lack inbound (ingress) rules, because a security group without ingress can block legitimate client traffic to the load balancer and indicates an incomplete network configuration that may cause availability issues.
 
 For each load balancer resource (for example, `AWS::ElasticLoadBalancing::LoadBalancer` or `AWS::ElasticLoadBalancingV2::LoadBalancer`), each entry in the `Properties.SecurityGroups` property must reference an `AWS::EC2::SecurityGroup` with ingress rules defined. The security group must either define a non-empty `SecurityGroupIngress` property or be targeted by one or more `AWS::EC2::SecurityGroupIngress` resources whose `GroupId` references it. Resources missing the `SecurityGroupIngress` key, with `SecurityGroupIngress` set to an empty list, or with no `AWS::EC2::SecurityGroupIngress` resources referencing the group will be flagged.

Secure example with an inline SecurityGroup ingress definition:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Allow HTTP to load balancer
    VpcId: vpc-123456
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 80
        ToPort: 80
        CidrIp: 0.0.0.0/0
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
    sgwithingress:
        Type: AWS::EC2::SecurityGroup
        Properties:
            GroupDescription: Limits security group egress traffic
            SecurityGroupIngress:
            -   IpProtocol: tcp
                FromPort: 80
                ToPort: 80
                CidrIp: 0.0.0.0/0
    MyLoadBalancer:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
            SecurityGroups:
            -   sgwithingress
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "sgwithingress": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Limits security group egress traffic",
        "SecurityGroupIngress": [
          {
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp",
            "FromPort": 80
          }
        ]
      }
    },
    "MyLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "SecurityGroups": [
          "sgwithingress"
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "sgwithoutingress": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Limits security group egress traffic"
      }
    },
    "MyLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "SecurityGroups": [
          "sgwithoutingress"
        ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
    sgwithoutingress:
        Type: AWS::EC2::SecurityGroup
        Properties:
            GroupDescription: Limits security group egress traffic
    MyLoadBalancer:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
            SecurityGroups:
            -   sgwithoutingress
```