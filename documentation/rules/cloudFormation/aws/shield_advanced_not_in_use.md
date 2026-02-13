---
title: "Shield Advanced not in use"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/shield_advanced_not_in_use"
  id: "ad7444cf-817a-4765-a79e-2145f7981faf"
  display_name: "Shield Advanced not in use"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ad7444cf-817a-4765-a79e-2145f7981faf`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fms-policy.html)

### Description

 Resources such as CloudFront distributions, Elastic Load Balancers, Global Accelerator accelerators, Elastic IPs, and Route 53 hosted zones should be protected by AWS Shield Advanced to reduce the risk of large-scale DDoS attacks that can cause prolonged service disruption and costly mitigation.

This check requires an `AWS::FMS::Policy` resource whose `Properties.SecurityServicePolicyData.Type` is set to `SHIELD_ADVANCED`. That FMS policy must include the relevant resource type in `Properties.ResourceTypeList` (for example, `AWS::CloudFront::Distribution`, `AWS::ElasticLoadBalancing::LoadBalancer`, `AWS::GlobalAccelerator::Accelerator`, `AWS::EC2::EIP`, or `AWS::Route53::HostedZone`). Resources without such an association will be flagged.

Secure configuration example:

```yaml
ShieldAdvancedFmsPolicy:
  Type: AWS::FMS::Policy
  Properties:
    PolicyName: ShieldAdvancedPolicy
    ResourceTypeList:
      - AWS::CloudFront::Distribution
      - AWS::ElasticLoadBalancing::LoadBalancer
      - AWS::GlobalAccelerator::Accelerator
      - AWS::EC2::EIP
      - AWS::Route53::HostedZone
    SecurityServicePolicyData:
      Type: SHIELD_ADVANCED
```


## Compliant Code Examples
```yaml
Resources:
  MyEIP:
    Type: AWS::EC2::EIP
    Properties:
      InstanceId: !Ref Logical name of an AWS::EC2::Instance resource
  Policy2:
    Type: AWS::FMS::Policy
    Properties:
      ExcludeResourceTags: true
      ResourceTags:
        - Key: resourceTag1
          Value: value
        - Key: resourceTag2
          Value: value
      IncludeMap:
        ACCOUNT:
          - !Ref AWS::AccountId
      PolicyName: TaggedPolicy
      RemediationEnabled: false
      ResourceType: ResourceTypeList
      ResourceTypeList:
        - AWS::EC2::EIP
      SecurityServicePolicyData:
        Type: SHIELD_ADVANCED
      DeleteAllPolicyResources: false
      Tags:
        - Key: tag1
          Value: value
        - Key: tag2
          Value: value

```

```json
{
  "Resources": {
    "MyEIP": {
      "Properties": {
        "InstanceId": "Logical name of an AWS::EC2::Instance resource"
      },
      "Type": "AWS::EC2::EIP"
    },
    "Policy2": {
      "Properties": {
        "DeleteAllPolicyResources": false,
        "ExcludeResourceTags": true,
        "IncludeMap": {
          "ACCOUNT": [
            "AWS::AccountId"
          ]
        },
        "PolicyName": "TaggedPolicy",
        "RemediationEnabled": false,
        "ResourceTags": [
          {
            "Key": "resourceTag1",
            "Value": "value"
          },
          {
            "Key": "resourceTag2",
            "Value": "value"
          }
        ],
        "ResourceType": "ResourceTypeList",
        "ResourceTypeList": [
          "AWS::EC2::EIP"
        ],
        "SecurityServicePolicyData": {
          "Type": "SHIELD_ADVANCED"
        },
        "Tags": [
          {
            "Key": "tag1",
            "Value": "value"
          },
          {
            "Key": "tag2",
            "Value": "value"
          }
        ]
      },
      "Type": "AWS::FMS::Policy"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "HostedZone": {
      "Properties": {
        "Name": "HostedZone",
        "QueryLoggingConfig": {
          "CloudWatchLogsLogGroupArn": "SomeCloudWatchLogGroupArn"
        }
      },
      "Type": "AWS::Route53::HostedZone"
    },
    "Policy": {
      "Properties": {
        "DeleteAllPolicyResources": false,
        "ExcludeResourceTags": true,
        "IncludeMap": {
          "ACCOUNT": [
            "AWS::AccountId"
          ]
        },
        "PolicyName": "TaggedPolicy",
        "RemediationEnabled": false,
        "ResourceTags": [
          {
            "Key": "resourceTag1",
            "Value": "value"
          },
          {
            "Key": "resourceTag2",
            "Value": "value"
          }
        ],
        "ResourceType": "ResourceTypeList",
        "ResourceTypeList": [
          "AWS::GlobalAccelerator::Accelerator"
        ],
        "SecurityServicePolicyData": {
          "Type": "SHIELD_ADVANCED"
        },
        "Tags": [
          {
            "Key": "tag1",
            "Value": "value"
          },
          {
            "Key": "tag2",
            "Value": "value"
          }
        ]
      },
      "Type": "AWS::FMS::Policy"
    }
  }
}

```

```yaml
Resources:
  HostedZone:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: "HostedZone"
      QueryLoggingConfig:
        CloudWatchLogsLogGroupArn: "SomeCloudWatchLogGroupArn"
  Policy:
    Type: AWS::FMS::Policy
    Properties:
      ExcludeResourceTags: true
      ResourceTags:
        - Key: resourceTag1
          Value: value
        - Key: resourceTag2
          Value: value
      IncludeMap:
        ACCOUNT:
          - !Ref AWS::AccountId
      PolicyName: TaggedPolicy
      RemediationEnabled: false
      ResourceType: ResourceTypeList
      ResourceTypeList:
        - AWS::GlobalAccelerator::Accelerator
      SecurityServicePolicyData:
        Type: SHIELD_ADVANCED
      DeleteAllPolicyResources: false
      Tags:
        - Key: tag1
          Value: value
        - Key: tag2
          Value: value

```