---
title: "ELB with security group without outbound rules"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elb_with_security_group_without_outbound_rules"
  id: "01d5a458-a6c4-452a-ac50-054d59275b7c"
  display_name: "ELB with security group without outbound rules"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `01d5a458-a6c4-452a-ac50-054d59275b7c`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html#cfn-ec2-securitygroup-securitygroupegress)

### Description

 Load balancers that are attached to security groups with no outbound rules, or without explicitly defined egress, may be unable to reach backend targets, perform health checks, or connect to logging and monitoring services. This can cause availability and operational failures.
 
 For load balancer resources (`AWS::ElasticLoadBalancing::LoadBalancer` and `AWS::ElasticLoadBalancingV2::LoadBalancer`), examine each security group referenced in the resource’s `SecurityGroups` list and validate the corresponding `AWS::EC2::SecurityGroup` defines the `SecurityGroupEgress` property. Resources missing `SecurityGroupEgress` or with `SecurityGroupEgress` set to an empty list will be flagged. The `SecurityGroupEgress` list must contain at least one egress rule that permits the required outbound traffic and should use narrow CIDRs, ports, or security-group destinations rather than broad `0.0.0.0/0` when possible.

Secure example with an explicit outbound rule allowing HTTPS egress:

```yaml
MySecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Allow load balancer outbound HTTPS to targets
    VpcId: vpc-01234567
    SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 10.0.0.0/16
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
    sgwithegress:
        Type: AWS::EC2::SecurityGroup
        Properties:
            GroupDescription: Limits security group egress traffic
            SecurityGroupEgress:
            -   IpProtocol: tcp
                FromPort: 80
                ToPort: 80
                CidrIp: 0.0.0.0/0
    MyLoadBalancer:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
            SecurityGroups:
            -   sgwithegress
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Resources": {
    "sgwithegress": {
      "Properties": {
        "GroupDescription": "Limits security group egress traffic",
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "CidrIp": "0.0.0.0/0"
          }
        ]
      },
      "Type": "AWS::EC2::SecurityGroup"
    },
    "MyLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "SecurityGroups": [
          "sgwithegress"
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
    "sgwithoutegress": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Limits security group egress traffic"
      }
    },
    "MyLoadBalancer": {
      "Type": "AWS::ElasticLoadBalancing::LoadBalancer",
      "Properties": {
        "SecurityGroups": [
          "sgwithoutegress"
        ]
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
    sgwithoutegress:
        Type: AWS::EC2::SecurityGroup
        Properties:
            GroupDescription: Limits security group egress traffic
    MyLoadBalancer:
        Type: AWS::ElasticLoadBalancing::LoadBalancer
        Properties:
            SecurityGroups:
            -   sgwithoutegress
```