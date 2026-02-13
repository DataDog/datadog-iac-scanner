---
title: "SageMaker data encryption disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/sagemaker_data_encryption_disabled"
  id: "709e6da6-fa1f-44cc-8f17-7f25f96dadbe"
  display_name: "SageMaker data encryption disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `709e6da6-fa1f-44cc-8f17-7f25f96dadbe`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sagemaker-notebookinstance.html)

### Description

 SageMaker notebook instances must specify a KMS key to encrypt data at rest. This helps protect notebook storage and snapshots from unauthorized access.

Check `AWS::SageMaker::NotebookInstance` resources for the `Properties.KmsKeyId` property. It must be defined as a non-empty string that identifies a valid KMS key (key ID, key ARN, or alias). Resources missing `KmsKeyId`, or with `KmsKeyId` set to `""`, will be flagged.

Secure configuration example:

```yaml
MyNotebook:
  Type: AWS::SageMaker::NotebookInstance
  Properties:
    NotebookInstanceName: my-notebook
    InstanceType: ml.t2.medium
    RoleArn: arn:aws:iam::123456789012:role/SageMakerRole
    KmsKeyId: !Ref MyKmsKey
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
Description: "Basic NotebookInstance test update to a different instance type"
Resources:
  BasicNotebookInstance:
    Type: "AWS::SageMaker::NotebookInstance"
    Properties:
      InstanceType: "ml.t2.large"
      RoleArn: !GetAtt ExecutionRole.Arn
      KmsKeyId: "Key"
  ExecutionRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          -
            Effect: "Allow"
            Principal:
              Service:
                - "sagemaker.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Path: "/"
      Policies:
        -
          PolicyName: "root"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              -
                Effect: "Allow"
                Action: "*"
                Resource: "*"
Outputs:
  BasicNotebookInstanceId:
    Value: !Ref BasicNotebookInstance
```

```json
{
  "Description": "Basic NotebookInstance test update to a different instance type",
  "Resources": {
    "ExecutionRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "sagemaker.amazonaws.com"
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
                  "Action": "*",
                  "Resource": "*"
                }
              ]
            }
          }
        ]
      }
    },
    "BasicNotebookInstance": {
      "Type": "AWS::SageMaker::NotebookInstance",
      "Properties": {
        "RoleArn": "ExecutionRole.Arn",
        "KmsKeyId": "Key",
        "InstanceType": "ml.t2.large"
      }
    }
  },
  "Outputs": {
    "BasicNotebookInstanceId": {
      "Value": "BasicNotebookInstance"
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Description": "Basic NotebookInstance test update to a different instance type",
  "Resources": {
    "BasicNotebookInstance2": {
      "Type": "AWS::SageMaker::NotebookInstance",
      "Properties": {
        "RoleArn": "ExecutionRole.Arn",
        "KmsKeyId": "some-kms-key",
        "InstanceType": "ml.t2.large"
      }
    },
    "BasicNotebookInstance3": {
      "Properties": {
        "InstanceType": "ml.t2.large",
        "RoleArn": "ExecutionRole.Arn",
        "KmsKeyId": ""
      },
      "Type": "AWS::SageMaker::NotebookInstance"
    },
    "ExecutionRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": [
                  "sagemaker.amazonaws.com"
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
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": "*",
                  "Resource": "*"
                }
              ]
            },
            "PolicyName": "root"
          }
        ]
      }
    },
    "BasicNotebookInstance": {
      "Type": "AWS::SageMaker::NotebookInstance",
      "Properties": {
        "InstanceType": "ml.t2.large",
        "RoleArn": "ExecutionRole.Arn"
      }
    }
  },
  "Outputs": {
    "BasicNotebookInstanceId": {
      "Value": "BasicNotebookInstance"
    }
  }
}

```

```yaml
#this is a problematic code where the query should report a result(s)
Description: "Basic NotebookInstance test update to a different instance type"
Resources:
  BasicNotebookInstance:
    Type: "AWS::SageMaker::NotebookInstance"
    Properties:
      InstanceType: "ml.t2.large"
      RoleArn: !GetAtt ExecutionRole.Arn
  BasicNotebookInstance2:
    Type: "AWS::SageMaker::NotebookInstance"
    Properties:
      InstanceType: "ml.t2.large"
      RoleArn: !GetAtt ExecutionRole.Arn
      KmsKeyId: 'some-kms-key'
  BasicNotebookInstance3:
    Type: "AWS::SageMaker::NotebookInstance"
    Properties:
      InstanceType: "ml.t2.large"
      RoleArn: !GetAtt ExecutionRole.Arn
      KmsKeyId : ""
  ExecutionRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          -
            Effect: "Allow"
            Principal:
              Service:
                - "sagemaker.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Path: "/"
      Policies:
        -
          PolicyName: "root"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              -
                Effect: "Allow"
                Action: "*"
                Resource: "*"
Outputs:
  BasicNotebookInstanceId:
    Value: !Ref BasicNotebookInstance

```