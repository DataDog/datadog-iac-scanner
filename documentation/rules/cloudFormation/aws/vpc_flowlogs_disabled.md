---
title: "VPC Flow Logs disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/vpc_flowlogs_disabled"
  id: "f6d299d2-21eb-41cc-b1e1-fe12d857500b"
  display_name: "VPC Flow Logs disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `f6d299d2-21eb-41cc-b1e1-fe12d857500b`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-flowlog.html)

### Description

 VPCs must have VPC Flow Logs enabled so network traffic metadata is recorded for detecting suspicious activity and supporting incident investigation and compliance audits.

For each `AWS::EC2::VPC` resource, ensure there is an `AWS::EC2::FlowLog` resource whose `Properties.ResourceId` references that VPC (for example, `Ref: MyVPC`) so traffic for that VPC is captured. Resources missing a flow log, or where the flow log's `ResourceId` does not reference the VPC, will be flagged. The flow log should also specify a valid destination (CloudWatch Logs or S3) via `LogDestination`/`LogDestinationType`.

Secure example (CloudFormation YAML):

```yaml
MyVPC:
  Type: AWS::EC2::VPC
  Properties:
    CidrBlock: 10.0.0.0/16

FlowLogGroup:
  Type: AWS::Logs::LogGroup

VPCFlowLog:
  Type: AWS::EC2::FlowLog
  Properties:
    ResourceType: VPC
    ResourceId: !Ref MyVPC
    TrafficType: ALL
    LogDestinationType: cloud-watch-logs
    LogDestination: !GetAtt FlowLogGroup.Arn
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'VPC: public and private subnets in two availability zones, a cloudonaut.io template'
Parameters:
  ClassB:
    Description: 'Class B of VPC (10.XXX.0.0/16)'
    Type: Number
    Default: 0
    ConstraintDescription: 'Must be in the range [0-255]'
    MinValue: 0
    MaxValue: 255
Resources:
  Role:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Principal:
            Service: 'vpc-flow-logs.amazonaws.com'
          Action: 'sts:AssumeRole'
      Policies:
      - PolicyName: 'flowlogs-policy'
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - 'logs:CreateLogStream'
            - 'logs:PutLogEvents'
            - 'logs:DescribeLogGroups'
            - 'logs:DescribeLogStreams'
            Resource: !GetAtt 'LogGroup.Arn'
  MyVPC:
    Type: 'AWS::EC2::VPC'
    Properties:
      CidrBlock: !Sub '10.${ClassB}.0.0/16'
      EnableDnsSupport: true
      EnableDnsHostnames: true
      InstanceTenancy: default
      Tags:
      - Key: Name
        Value: !Sub '10.${ClassB}.0.0/16'
  LogGroup:
    Type: 'AWS::Logs::LogGroup'
    Properties:
      RetentionInDays: 14
  FlowLog:
    Type: 'AWS::EC2::FlowLog'
    Properties:
      DeliverLogsPermissionArn: !GetAtt 'Role.Arn'
      LogGroupName: !Ref LogGroup
      ResourceId: !Ref MyVPC
      ResourceType: 'VPC'
      TrafficType: ACCEPT
```

```json
{
  "Description": "VPC: public and private subnets in two availability zones, a cloudonaut.io template",
  "Parameters": {
    "ClassB": {
      "Description": "Class B of VPC (10.XXX.0.0/16)",
      "Type": "Number",
      "Default": 0,
      "ConstraintDescription": "Must be in the range [0-255]",
      "MinValue": 0,
      "MaxValue": 255
    }
  },
  "Resources": {
    "Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Effect": "Allow",
              "Principal": {
                "Service": "vpc-flow-logs.amazonaws.com"
              }
            }
          ]
        },
        "Policies": [
          {
            "PolicyDocument": {
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams"
                  ],
                  "Resource": "LogGroup.Arn"
                }
              ],
              "Version": "2012-10-17"
            },
            "PolicyName": "flowlogs-policy"
          }
        ]
      }
    },
    "MyVPC": {
      "Properties": {
        "InstanceTenancy": "default",
        "Tags": [
          {
            "Key": "Name",
            "Value": "10.${ClassB}.0.0/16"
          }
        ],
        "CidrBlock": "10.${ClassB}.0.0/16",
        "EnableDnsSupport": true,
        "EnableDnsHostnames": true
      },
      "Type": "AWS::EC2::VPC"
    },
    "LogGroup": {
      "Type": "AWS::Logs::LogGroup",
      "Properties": {
        "RetentionInDays": 14
      }
    },
    "FlowLog": {
      "Type": "AWS::EC2::FlowLog",
      "Properties": {
        "DeliverLogsPermissionArn": "Role.Arn",
        "LogGroupName": "LogGroup",
        "ResourceId": "MyVPC",
        "ResourceType": "VPC",
        "TrafficType": "ACCEPT"
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "VPC: public and private subnets in two availability zones, a cloudonaut.io template",
  "Parameters": {
    "ClassB": {
      "MaxValue": 255,
      "Description": "Class B of VPC (10.XXX.0.0/16)",
      "Type": "Number",
      "Default": 0,
      "ConstraintDescription": "Must be in the range [0-255]",
      "MinValue": 0
    }
  },
  "Resources": {
    "Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "vpc-flow-logs.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Policies": [
          {
            "PolicyName": "flowlogs-policy",
            "PolicyDocument": {
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams"
                  ],
                  "Resource": "LogGroup.Arn"
                }
              ],
              "Version": "2012-10-17"
            }
          }
        ]
      }
    },
    "MyVPC": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "EnableDnsSupport": true,
        "EnableDnsHostnames": true,
        "InstanceTenancy": "default",
        "Tags": [
          {
            "Key": "Name",
            "Value": "10.${ClassB}.0.0/16"
          }
        ],
        "CidrBlock": "10.${ClassB}.0.0/16"
      }
    },
    "LogGroup": {
      "Type": "AWS::Logs::LogGroup",
      "Properties": {
        "RetentionInDays": 14
      }
    },
    "FlowLog": {
      "Type": "AWS::EC2::FlowLog",
      "Properties": {
        "DeliverLogsPermissionArn": "Role.Arn",
        "LogGroupName": "LogGroup",
        "ResourceId": "MyVPC1",
        "ResourceType": "VPC",
        "TrafficType": "ACCEPT"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'VPC: public and private subnets in two availability zones, a cloudonaut.io template'
Parameters:
  ClassB:
    Description: 'Class B of VPC (10.XXX.0.0/16)'
    Type: Number
    Default: 0
    ConstraintDescription: 'Must be in the range [0-255]'
    MinValue: 0
    MaxValue: 255
Resources:
  Role:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Principal:
            Service: 'vpc-flow-logs.amazonaws.com'
          Action: 'sts:AssumeRole'
      Policies:
      - PolicyName: 'flowlogs-policy'
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - 'logs:CreateLogStream'
            - 'logs:PutLogEvents'
            - 'logs:DescribeLogGroups'
            - 'logs:DescribeLogStreams'
            Resource: !GetAtt 'LogGroup.Arn'
  MyVPC:
    Type: 'AWS::EC2::VPC'
    Properties:
      CidrBlock: !Sub '10.${ClassB}.0.0/16'
      EnableDnsSupport: true
      EnableDnsHostnames: true
      InstanceTenancy: default
      Tags:
      - Key: Name
        Value: !Sub '10.${ClassB}.0.0/16'
  LogGroup:
    Type: 'AWS::Logs::LogGroup'
    Properties:
      RetentionInDays: 14
  FlowLog:
    Type: 'AWS::EC2::FlowLog'
    Properties:
      DeliverLogsPermissionArn: !GetAtt 'Role.Arn'
      LogGroupName: !Ref LogGroup
      ResourceId: !Ref MyVPC1
      ResourceType: 'VPC'
      TrafficType: ACCEPT
```