---
title: "Inline policies are attached to an ECS service"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/inline_policies_are_attached_to_ecs_service"
  id: "9e8c89b3-7997-4d15-93e4-7911b9db99fd"
  display_name: "Inline policies are attached to an ECS service"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9e8c89b3-7997-4d15-93e4-7911b9db99fd`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ecs-service.html)

### Description

ECS services must reference an IAM role, not an IAM policy, because pointing the service `Role` property to a policy resource can break permission binding, make access controls harder to manage and audit, and increase the chance of privilege misconfiguration. Check `AWS::ECS::Service` resources' `Properties.Role`. The value must be a reference to an `AWS::IAM::Role` (logical ID or ARN) and must not be the logical ID of an `AWS::IAM::Policy` resource. Attach permissions to that role using `ManagedPolicyArns`, an `AWS::IAM::ManagedPolicy`, or inline policies defined on the `AWS::IAM::Role` itself. ECS services whose `Role` property refers to an `AWS::IAM::Policy` logical ID will be flagged.

Secure configuration example:

```yaml
MyEcsRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: ecs-tasks.amazonaws.com
          Action: sts:AssumeRole
    ManagedPolicyArns:
      - arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

MyEcsService:
  Type: AWS::ECS::Service
  Properties:
    Role: !Ref MyEcsRole
```

## Compliant Code Examples
```yaml

Resources:
  InlinePolicy:
    Type: AWS::ECS::Service
    DependsOn:
    - Listener
    Properties:
      LoadBalancers:
      - TargetGroupArn:
          Ref: TargetGroup
        ContainerPort: 80
        ContainerName: sample-app
      Cluster:
        Ref: ECSCluster
  IAMPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: root
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'

```

```json
{
  "Resources": {
    "IAMPolicy": {
      "Properties": {
        "PolicyName": "root",
        "PolicyDocument": {
          "Version": "2012-10-17T00:00:00Z",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      },
      "Type": "AWS::IAM::Policy"
    },
    "InlinePolicy": {
      "DependsOn": [
        "Listener"
      ],
      "Properties": {
        "LoadBalancers": [
          {
            "TargetGroupArn": {
              "Ref": "TargetGroup"
            },
            "ContainerPort": 80,
            "ContainerName": "sample-app"
          }
        ],
        "Cluster": {
          "Ref": "ECSCluster"
        }
      },
      "Type": "AWS::ECS::Service"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "InlinePolicy": {
      "Type": "AWS::ECS::Service",
      "DependsOn": [
        "Listener"
      ],
      "Properties": {
        "Role": {
          "Ref": "IAMPolicy"
        },
        "LoadBalancers": [
          {
            "TargetGroupArn": {
              "Ref": "TargetGroup"
            },
            "ContainerPort": 80,
            "ContainerName": "sample-app"
          }
        ],
        "Cluster": {
          "Ref": "ECSCluster"
        }
      }
    },
    "IAMPolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
        "PolicyName": "root",
        "PolicyDocument": {
          "Version": "2012-10-17T00:00:00Z",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      }
    }
  }
}

```

```yaml
Resources:
  InlinePolicy:
    Type: AWS::ECS::Service
    DependsOn:
    - Listener
    Properties:
      Role:
        Ref: IAMPolicy
      LoadBalancers:
      - TargetGroupArn:
          Ref: TargetGroup
        ContainerPort: 80
        ContainerName: sample-app
      Cluster:
        Ref: ECSCluster
  IAMPolicy:
    Type: 'AWS::IAM::Policy'
    Properties:
      PolicyName: root
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'

```