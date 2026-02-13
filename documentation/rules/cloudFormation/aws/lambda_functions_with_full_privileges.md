---
title: "Lambda functions with full privileges"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/lambda_functions_with_full_privileges"
  id: "a0ae0a4e-712b-4115-8112-51b9eeed9d69"
  display_name: "Lambda functions with full privileges"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `a0ae0a4e-712b-4115-8112-51b9eeed9d69`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html)

### Description

 Lambda functions must not be assigned IAM roles whose inline policies grant full administrative privileges, because a compromised function with full permissions can exfiltrate data, modify or delete resources, or escalate privileges across your account. This rule inspects `AWS::Lambda::Function` resources' `Properties.Role` reference (when the role is defined in the same template) and examines the referenced role's `Resources.<role>.Properties.Policies[].PolicyDocument.Statement[]`. A statement will be flagged when `Effect` is `Allow` and both `Action` and `Resource` are `*` (including arrays that contain `*`). To remediate, follow least privilege. Replace wildcard actions and resources with explicit actions and scoped ARNs, or attach narrowly scoped managed policies. Inline policies must not simultaneously allow `Action: '*'` and `Resource: '*'`.

Secure example (inline role policy scoped to a single S3 bucket):

```yaml
MyLambdaRole:
  Type: AWS::IAM::Role
  Properties:
    AssumeRolePolicyDocument:
      Statement:
        - Effect: Allow
          Principal:
            Service: lambda.amazonaws.com
          Action: sts:AssumeRole
    Policies:
      - PolicyName: LambdaS3ReadOnly
        PolicyDocument:
          Statement:
            - Effect: Allow
              Action:
                - s3:GetObject
              Resource: arn:aws:s3:::example-bucket/* 
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ExistingSecurityGroups:
    Type: List<AWS::EC2::SecurityGroup::Id>
  ExistingVPC:
    Type: AWS::EC2::VPC::Id
    Description: The VPC ID that includes the security groups in the ExistingSecurityGroups
      parameter.
  InstanceType:
    Type: String
    Default: t2.micro
    AllowedValues:
    - t2.micro
    - m1.small
Resources:
  SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow HTTP traffic to the host
      VpcId:
        Ref: ExistingVPC
      SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: '80'
        ToPort: '80'
        CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: '80'
        ToPort: '80'
        CidrIp: 0.0.0.0/0
  AllSecurityGroups:
    Type: Custom::Split
    Properties:
      ServiceToken: !GetAtt AppendItemToListFunction.Arn
      List:
        Ref: ExistingSecurityGroups
      AppendedItem:
        Ref: SecurityGroup
  AppendItemToListFunction:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Code:
        ZipFile: |
          var response = require('cfn-response');
          exports.handler = function(event, context) {
             var responseData = {Value: event.ResourceProperties.List};
             responseData.Value.push(event.ResourceProperties.AppendedItem);
             response.send(event, context, response.SUCCESS, responseData);
          };
      Runtime: nodejs8.10
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0ff8a91507f77f867
      SecurityGroupIds: !GetAtt AllSecurityGroups.Value
      InstanceType:
        Ref: InstanceType
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Principal:
            Service:
            - lambda.amazonaws.com
          Action:
          - sts:AssumeRole
      Path: "/"
      Policies:
      - PolicyName: root
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - iam:ChangePassword
            Resource: arn:aws:iam::account-ID-without-hyphens:user/Bob

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "ExistingSecurityGroups": {
      "Type": "List\u003cAWS::EC2::SecurityGroup::Id\u003e"
    },
    "ExistingVPC": {
      "Description": "The VPC ID that includes the security groups in the ExistingSecurityGroups parameter.",
      "Type": "AWS::EC2::VPC::Id"
    },
    "InstanceType": {
      "Type": "String",
      "Default": "t2.micro",
      "AllowedValues": [
        "t2.micro",
        "m1.small"
      ]
    }
  },
  "Resources": {
    "SecurityGroup": {
      "Properties": {
        "GroupDescription": "Allow HTTP traffic to the host",
        "VpcId": {
          "Ref": "ExistingVPC"
        },
        "SecurityGroupIngress": [
          {
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp"
          }
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "0.0.0.0/0"
          }
        ]
      },
      "Type": "AWS::EC2::SecurityGroup"
    },
    "AllSecurityGroups": {
      "Type": "Custom::Split",
      "Properties": {
        "ServiceToken": "AppendItemToListFunction.Arn",
        "List": {
          "Ref": "ExistingSecurityGroups"
        },
        "AppendedItem": {
          "Ref": "SecurityGroup"
        }
      }
    },
    "AppendItemToListFunction": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Handler": "index.handler",
        "Role": "LambdaExecutionRole.Arn",
        "Code": {
          "ZipFile": "var response = require('cfn-response');\nexports.handler = function(event, context) {\n   var responseData = {Value: event.ResourceProperties.List};\n   responseData.Value.push(event.ResourceProperties.AppendedItem);\n   response.send(event, context, response.SUCCESS, responseData);\n};\n"
        },
        "Runtime": "nodejs8.10"
      }
    },
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-0ff8a91507f77f867",
        "SecurityGroupIds": "AllSecurityGroups.Value",
        "InstanceType": {
          "Ref": "InstanceType"
        }
      }
    },
    "LambdaExecutionRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "lambda.amazonaws.com"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/",
        "Policies": [
          {
            "PolicyName": "root",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "iam:ChangePassword"
                  ],
                  "Resource": "arn:aws:iam::account-ID-without-hyphens:user/Bob"
                }
              ]
            }
          }
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "InstanceType": {
      "Default": "t2.micro",
      "AllowedValues": [
        "t2.micro",
        "m1.small"
      ],
      "Type": "String"
    },
    "ExistingSecurityGroups": {
      "Type": "List\u003cAWS::EC2::SecurityGroup::Id\u003e"
    },
    "ExistingVPC": {
      "Description": "The VPC ID that includes the security groups in the ExistingSecurityGroups parameter.",
      "Type": "AWS::EC2::VPC::Id"
    }
  },
  "Resources": {
    "SecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Allow HTTP traffic to the host",
        "VpcId": {
          "Ref": "ExistingVPC"
        },
        "SecurityGroupIngress": [
          {
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "0.0.0.0/0",
            "IpProtocol": "tcp"
          }
        ],
        "SecurityGroupEgress": [
          {
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "0.0.0.0/0"
          }
        ]
      }
    },
    "AllSecurityGroups": {
      "Type": "Custom::Split",
      "Properties": {
        "ServiceToken": "AppendItemToListFunction.Arn",
        "List": {
          "Ref": "ExistingSecurityGroups"
        },
        "AppendedItem": {
          "Ref": "SecurityGroup"
        }
      }
    },
    "AppendItemToListFunction": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Code": {
          "ZipFile": "var response = require('cfn-response');\nexports.handler = function(event, context) {\n   var responseData = {Value: event.ResourceProperties.List};\n   responseData.Value.push(event.ResourceProperties.AppendedItem);\n   response.send(event, context, response.SUCCESS, responseData);\n};\n"
        },
        "Runtime": "nodejs8.10",
        "Handler": "index.handler",
        "Role": "LambdaExecutionRole.Arn"
      }
    },
    "MyEC2Instance": {
      "Type": "AWS::EC2::Instance",
      "Properties": {
        "ImageId": "ami-0ff8a91507f77f867",
        "SecurityGroupIds": "AllSecurityGroups.Value",
        "InstanceType": {
          "Ref": "InstanceType"
        }
      }
    },
    "LambdaExecutionRole": {
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "lambda.amazonaws.com"
                ]
              },
              "Action": [
                "sts:AssumeRole"
              ]
            }
          ]
        },
        "Path": "/",
        "Policies": [
          {
            "PolicyName": "root",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "*"
                  ],
                  "Resource": "arn:aws:logs:*:*:*"
                }
              ]
            }
          }
        ]
      },
      "Type": "AWS::IAM::Role"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ExistingSecurityGroups:
    Type: List<AWS::EC2::SecurityGroup::Id>
  ExistingVPC:
    Type: AWS::EC2::VPC::Id
    Description: The VPC ID that includes the security groups in the ExistingSecurityGroups
      parameter.
  InstanceType:
    Type: String
    Default: t2.micro
    AllowedValues:
    - t2.micro
    - m1.small
Resources:
  SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Allow HTTP traffic to the host
      VpcId:
        Ref: ExistingVPC
      SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: '80'
        ToPort: '80'
        CidrIp: 0.0.0.0/0
      SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: '80'
        ToPort: '80'
        CidrIp: 0.0.0.0/0
  AllSecurityGroups:
    Type: Custom::Split
    Properties:
      ServiceToken: !GetAtt AppendItemToListFunction.Arn
      List:
        Ref: ExistingSecurityGroups
      AppendedItem:
        Ref: SecurityGroup
  AppendItemToListFunction:
    Type: AWS::Lambda::Function
    Properties:
      Handler: index.handler
      Role: !GetAtt LambdaExecutionRole.Arn
      Code:
        ZipFile: |
          var response = require('cfn-response');
          exports.handler = function(event, context) {
             var responseData = {Value: event.ResourceProperties.List};
             responseData.Value.push(event.ResourceProperties.AppendedItem);
             response.send(event, context, response.SUCCESS, responseData);
          };
      Runtime: nodejs8.10
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-0ff8a91507f77f867
      SecurityGroupIds: !GetAtt AllSecurityGroups.Value
      InstanceType:
        Ref: InstanceType
  LambdaExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
        - Effect: Allow
          Principal:
            Service:
            - lambda.amazonaws.com
          Action:
          - sts:AssumeRole
      Path: "/"
      Policies:
      - PolicyName: root
        PolicyDocument:
          Version: '2012-10-17'
          Statement:
          - Effect: Allow
            Action:
            - "*"
            Resource: arn:aws:logs:*:*:*

```