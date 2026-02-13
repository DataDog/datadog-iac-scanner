---
title: "ELBv2 ALB access log disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/elb_v2_alb_access_log_disabled"
  id: "c62e8b7d-1fdf-4050-ac4c-76ba9e1d9621"
  display_name: "ELBv2 ALB access log disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `c62e8b7d-1fdf-4050-ac4c-76ba9e1d9621`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html#cfn-elasticloadbalancingv2-loadbalancer-loadbalancerattributes-key)

### Description

Application Load Balancers must have access logging enabled so you retain detailed request records for incident investigation and traffic analysis. Without logs, security incidents are harder to investigate and you may not meet auditing or compliance requirements.
 
 For CloudFormation, check `AWS::ElasticLoadBalancingV2::LoadBalancer` resources have a `LoadBalancerAttributes` entry with `Key` equal to `access_logs.s3.enabled` and `Value` set to `true` (or the string `"true"` in templates). Resources missing the `LoadBalancerAttributes` property, or that include `access_logs.s3.enabled` with `Value` set to `false` (or `"false"`), will be flagged as non-compliant. 
 
 Secure CloudFormation example:

```yaml
MyLoadBalancer:
  Type: AWS::ElasticLoadBalancingV2::LoadBalancer
  Properties:
    Name: my-alb
    Type: application
    LoadBalancerAttributes:
      - Key: access_logs.s3.enabled
        Value: "true"
      - Key: access_logs.s3.bucket
        Value: my-alb-logs-bucket
      - Key: access_logs.s3.prefix
        Value: alb-logs/
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A simple EC2 instance
Parameters:
  EnvironmentName:
    Description: An environment name that will be prefixed to resource names
    Type: String

  VPC:
    Type: AWS::EC2::VPC::Id
    Description: Choose which VPC the Application Load Balancer should be deployed to

  Subnets:
    Description: Choose which subnets the Application Load Balancer should be deployed to
    Type: List<AWS::EC2::Subnet::Id>

  SecurityGroup:
    Description: Select the Security Group to apply to the Application Load Balancer
    Type: AWS::EC2::SecurityGroup::Id
Resources:
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: !Ref EnvironmentName
      Subnets: !Ref Subnets
      SecurityGroups:
        - !Ref SecurityGroup
      Tags:
        - Key: Name
          Value: !Ref EnvironmentName
      LoadBalancerAttributes:
        - Key: access_logs.s3.enabled
          Value: true

```

```json
{
  "Description": "A simple EC2 instance",
  "Parameters": {
    "EnvironmentName": {
      "Description": "An environment name that will be prefixed to resource names",
      "Type": "String"
    },
    "VPC": {
      "Type": "AWS::EC2::VPC::Id",
      "Description": "Choose which VPC the Application Load Balancer should be deployed to"
    },
    "Subnets": {
      "Description": "Choose which subnets the Application Load Balancer should be deployed to",
      "Type": "List\u003cAWS::EC2::Subnet::Id\u003e"
    },
    "SecurityGroup": {
      "Description": "Select the Security Group to apply to the Application Load Balancer",
      "Type": "AWS::EC2::SecurityGroup::Id"
    }
  },
  "Resources": {
    "LoadBalancer": {
      "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "Properties": {
        "SecurityGroups": [
          "SecurityGroup"
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "EnvironmentName"
          }
        ],
        "LoadBalancerAttributes": [
          {
            "Key": "access_logs.s3.enabled",
            "Value": true
          }
        ],
        "Name": "EnvironmentName",
        "Subnets": "Subnets"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
## Non-Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A simple EC2 instance
Parameters:
  EnvironmentName:
    Description: An environment name that will be prefixed to resource names
    Type: String

  VPC:
    Type: AWS::EC2::VPC::Id
    Description: Choose which VPC the Application Load Balancer should be deployed to

  Subnets:
    Description: Choose which subnets the Application Load Balancer should be deployed to
    Type: List<AWS::EC2::Subnet::Id>

  SecurityGroup:
    Description: Select the Security Group to apply to the Application Load Balancer
    Type: AWS::EC2::SecurityGroup::Id
Resources:
  LoadBalancertest:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: !Ref EnvironmentName
      Subnets: !Ref Subnets
      SecurityGroups:
        - !Ref SecurityGroup
      Tags:
        - Key: Name
          Value: !Ref EnvironmentName
      LoadBalancerAttributes:
        - Key: access_logs.s3.enabled
          Value: false

```

```json
{
  "Parameters": {
    "SecurityGroup": {
      "Description": "Select the Security Group to apply to the Application Load Balancer",
      "Type": "AWS::EC2::SecurityGroup::Id"
    },
    "EnvironmentName": {
      "Description": "An environment name that will be prefixed to resource names",
      "Type": "String"
    },
    "VPC": {
      "Type": "AWS::EC2::VPC::Id",
      "Description": "Choose which VPC the Application Load Balancer should be deployed to"
    },
    "Subnets": {
      "Description": "Choose which subnets the Application Load Balancer should be deployed to",
      "Type": "List\u003cAWS::EC2::Subnet::Id\u003e"
    }
  },
  "Resources": {
    "LoadBalancer": {
      "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "Properties": {
        "Name": "EnvironmentName",
        "Subnets": "Subnets",
        "SecurityGroups": [
          "SecurityGroup"
        ],
        "Tags": [
          {
            "Key": "Name",
            "Value": "EnvironmentName"
          }
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "A simple EC2 instance"
}

```

```json
{
  "Description": "A simple EC2 instance",
  "Parameters": {
    "SecurityGroup": {
      "Description": "Select the Security Group to apply to the Application Load Balancer",
      "Type": "AWS::EC2::SecurityGroup::Id"
    },
    "EnvironmentName": {
      "Description": "An environment name that will be prefixed to resource names",
      "Type": "String"
    },
    "VPC": {
      "Type": "AWS::EC2::VPC::Id",
      "Description": "Choose which VPC the Application Load Balancer should be deployed to"
    },
    "Subnets": {
      "Description": "Choose which subnets the Application Load Balancer should be deployed to",
      "Type": "List\u003cAWS::EC2::Subnet::Id\u003e"
    }
  },
  "Resources": {
    "LoadBalancertest": {
      "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "Properties": {
        "Name": "EnvironmentName",
        "Subnets": "Subnets",
        "SecurityGroups": [
          "SecurityGroup"
        ],
        "Tags": [
          {
            "Value": "EnvironmentName",
            "Key": "Name"
          }
        ],
        "LoadBalancerAttributes": [
          {
            "Key": "access_logs.s3.enabled",
            "Value": false
          }
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```