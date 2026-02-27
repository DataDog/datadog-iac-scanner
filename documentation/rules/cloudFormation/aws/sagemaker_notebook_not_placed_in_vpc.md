---
title: "SageMaker notebook not placed in VPC"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/sagemaker_notebook_not_placed_in_vpc"
  id: "9c7028d9-04c2-45be-b8b2-1188ccaefb36"
  display_name: "SageMaker notebook not placed in VPC"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `9c7028d9-04c2-45be-b8b2-1188ccaefb36`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/sagemaker/latest/dg/security_iam_id-based-policy-examples.html#sagemaker-condition-nbi-lockdown)

### Description

SageMaker notebook instances must be launched inside a VPC to prevent unintended public network exposure. This also enables network controls such as security groups, VPC endpoints, and flow logging.

In CloudFormation, `AWS::SageMaker::NotebookInstance` resources must include the `Properties.SubnetId` property and reference a subnet in the intended VPC. Also specify `Properties.SecurityGroupIds` to restrict inbound access, and configure any required VPC endpoints (for example, for S3 and ECR). Resources missing `SubnetId` will be flagged.

Secure configuration example:

```yaml
MyNotebook:
  Type: AWS::SageMaker::NotebookInstance
  Properties:
    NotebookInstanceName: my-notebook
    InstanceType: ml.t2.medium
    SubnetId: subnet-0123456789abcdef0
    SecurityGroupIds:
      - sg-0123456789abcdef0
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "NotebookInstance"
Resources:
  NotebookInstance:
    Type: "AWS::SageMaker::NotebookInstance"
    DependsOn: [ MountTarget1, MountTarget2, MountTarget3, VpcS3Endpoint ]
    Properties:
      NotebookInstanceName: !Ref NotebookInstanceName
      InstanceType: !Ref NotebookInstanceType
      RoleArn: !GetAtt ExecutionRole.Arn
      RootAccess: Enabled
      SecurityGroupIds:
        - !GetAtt VpcSecurityGroup.GroupId
      SubnetId: !Ref PrivateSubnet1
      DirectInternetAccess: Disabled
      AdditionalCodeRepositories: !If
        - CreateCodeRepo
        - [!GetAtt CodeRepo.CodeRepositoryName]
        - !Ref 'AWS::NoValue'
      LifecycleConfigName: !GetAtt NotebookStartConfig.NotebookInstanceLifecycleConfigName
      VolumeSizeInGB: !Ref EbsVolumeSize
      Tags:
        - Key: Name
          Value: !Ref 'AWS::StackName'
  Vpc:
    Type: 'AWS::EC2::VPC'
    Properties:
      CidrBlock: !Ref VpcCIDR
      EnableDnsSupport: 'true'
      EnableDnsHostnames: 'true'
      Tags:
        - Key: Name
          Value: !Ref 'AWS::StackName'

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "NotebookInstance",
  "Resources": {
    "NotebookInstance": {
      "Type": "AWS::SageMaker::NotebookInstance",
      "DependsOn": [
        "MountTarget1",
        "MountTarget2",
        "MountTarget3",
        "VpcS3Endpoint"
      ],
      "Properties": {
        "InstanceType": "NotebookInstanceType",
        "RoleArn": "ExecutionRole.Arn",
        "SecurityGroupIds": [
          "VpcSecurityGroup.GroupId"
        ],
        "AdditionalCodeRepositories": [
          "CreateCodeRepo",
          [
            "CodeRepo.CodeRepositoryName"
          ],
          "AWS::NoValue"
        ],
        "VolumeSizeInGB": "EbsVolumeSize",
        "Tags": [
          {
            "Key": "Name",
            "Value": "AWS::StackName"
          }
        ],
        "NotebookInstanceName": "NotebookInstanceName",
        "SubnetId": "PrivateSubnet1",
        "DirectInternetAccess": "Disabled",
        "LifecycleConfigName": "NotebookStartConfig.NotebookInstanceLifecycleConfigName",
        "RootAccess": "Enabled"
      }
    },
    "Vpc": {
      "Properties": {
        "CidrBlock": "VpcCIDR",
        "EnableDnsSupport": "true",
        "EnableDnsHostnames": "true",
        "Tags": [
          {
            "Key": "Name",
            "Value": "AWS::StackName"
          }
        ]
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
  "Description": "NotebookInstance",
  "Resources": {
    "Vpc": {
      "Type": "AWS::EC2::VPC",
      "Properties": {
        "CidrBlock": "VpcCIDR",
        "EnableDnsSupport": "true",
        "EnableDnsHostnames": "true",
        "Tags": [
          {
            "Key": "Name",
            "Value": "AWS::StackName"
          }
        ]
      }
    },
    "NotebookInstance": {
      "Type": "AWS::SageMaker::NotebookInstance",
      "DependsOn": [
        "MountTarget1",
        "MountTarget2",
        "MountTarget3",
        "VpcS3Endpoint"
      ],
      "Properties": {
        "VolumeSizeInGB": "EbsVolumeSize",
        "Tags": [
          {
            "Key": "Name",
            "Value": "AWS::StackName"
          }
        ],
        "NotebookInstanceName": "NotebookInstanceName",
        "SecurityGroupIds": [
          "VpcSecurityGroup.GroupId"
        ],
        "DirectInternetAccess": "Disabled",
        "AdditionalCodeRepositories": [
          "CreateCodeRepo",
          [
            "CodeRepo.CodeRepositoryName"
          ],
          "AWS::NoValue"
        ],
        "LifecycleConfigName": "NotebookStartConfig.NotebookInstanceLifecycleConfigName",
        "InstanceType": "NotebookInstanceType",
        "RoleArn": "ExecutionRole.Arn",
        "RootAccess": "Enabled"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "NotebookInstance"
Resources:
  NotebookInstance:
    Type: "AWS::SageMaker::NotebookInstance"
    DependsOn: [ MountTarget1, MountTarget2, MountTarget3, VpcS3Endpoint ]
    Properties:
      NotebookInstanceName: !Ref NotebookInstanceName
      InstanceType: !Ref NotebookInstanceType
      RoleArn: !GetAtt ExecutionRole.Arn
      RootAccess: Enabled
      SecurityGroupIds:
        - !GetAtt VpcSecurityGroup.GroupId
      DirectInternetAccess: Disabled
      AdditionalCodeRepositories: !If
        - CreateCodeRepo
        - [!GetAtt CodeRepo.CodeRepositoryName]
        - !Ref 'AWS::NoValue'
      LifecycleConfigName: !GetAtt NotebookStartConfig.NotebookInstanceLifecycleConfigName
      VolumeSizeInGB: !Ref EbsVolumeSize
      Tags:
        - Key: Name
          Value: !Ref 'AWS::StackName'
  Vpc:
    Type: 'AWS::EC2::VPC'
    Properties:
      CidrBlock: !Ref VpcCIDR
      EnableDnsSupport: 'true'
      EnableDnsHostnames: 'true'
      Tags:
        - Key: Name
          Value: !Ref 'AWS::StackName'

```