---
title: "EFS without tags"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/efs_without_tags"
  id: "08e39832-5e42-4304-98a0-aa5b43393162"
  display_name: "EFS without tags"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `08e39832-5e42-4304-98a0-aa5b43393162`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-efs-filesystem.html)

### Description

 Amazon EFS file systems should be tagged to enable asset identification and to support automated policy and access controls. Missing tags make it harder to track ownership and enforce tag-based security or lifecycle rules.
 
 The CloudFormation resource `AWS::EFS::FileSystem` must include the `FileSystemTags` property, and it must be defined (not `null`). Resources missing `FileSystemTags` or with it set to `null` will be flagged for remediation.

Secure configuration example:

```yaml
MyEFS:
  Type: AWS::EFS::FileSystem
  Properties:
    FileSystemTags:
      - Key: Name
        Value: my-efs
      - Key: Environment
        Value: production
```


## Compliant Code Examples
```yaml

AWSTemplateFormatVersion: '2010-09-09'
Description: Create Elastic File System
Parameters:
  Owner:
    Type: String
    Default: FirstName LastName
  Project:
    Type: String
    Default: EFS Mount
  VPC:
    Type: AWS::EC2::VPC::Id
  Subnet1:
    Type: AWS::EC2::Subnet::Id
Resources:
  FileSystem:
    Type: AWS::EFS::FileSystem
    Properties:
      FileSystemTags:
      - Key: Name
        Value: !Ref AWS::StackName
      - Key: Owner
        Value: !Ref Owner
      - Key: Project
        Value: !Ref Project
  MountTarget1:
    Type: AWS::EFS::MountTarget
    Properties:
      FileSystemId: !Ref FileSystem
      SubnetId: !Ref Subnet1
      SecurityGroups:
      - !Ref EfsSecurityGroup
  EfsSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Instance to EFS Mount Access
      VpcId: !Ref VPC
      Tags:
      - Key: Name
        Value: !Ref AWS::StackName
      - Key: Owner
        Value: !Ref Owner
      - Key: Project
        Value: !Ref Project

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Create Elastic File System",
  "Parameters": {
    "VPC": {
      "Type": "AWS::EC2::VPC::Id"
    },
    "Subnet1": {
      "Type": "AWS::EC2::Subnet::Id"
    },
    "Owner": {
      "Type": "String",
      "Default": "FirstName LastName"
    },
    "Project": {
      "Type": "String",
      "Default": "EFS Mount"
    }
  },
  "Resources": {
    "EfsSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "Tags": [
          {
            "Key": "Name",
            "Value": "AWS::StackName"
          },
          {
            "Key": "Owner",
            "Value": "Owner"
          },
          {
            "Key": "Project",
            "Value": "Project"
          }
        ],
        "GroupDescription": "Instance to EFS Mount Access",
        "VpcId": "VPC"
      }
    },
    "FileSystem": {
      "Type": "AWS::EFS::FileSystem",
      "Properties": {
        "FileSystemTags": [
          {
            "Key": "Name",
            "Value": "AWS::StackName"
          },
          {
            "Key": "Owner",
            "Value": "Owner"
          },
          {
            "Key": "Project",
            "Value": "Project"
          }
        ]
      }
    },
    "MountTarget1": {
      "Type": "AWS::EFS::MountTarget",
      "Properties": {
        "FileSystemId": "FileSystem",
        "SubnetId": "Subnet1",
        "SecurityGroups": [
          "EfsSecurityGroup"
        ]
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Parameters": {
    "Project": {
      "Default": "EFS Mount",
      "Type": "String"
    },
    "VPC": {
      "Type": "AWS::EC2::VPC::Id"
    },
    "Subnet1": {
      "Type": "AWS::EC2::Subnet::Id"
    },
    "Owner": {
      "Type": "String",
      "Default": "FirstName LastName"
    }
  },
  "Resources": {
    "EfsSecurityGroup": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "Instance to EFS Mount Access",
        "VpcId": "VPC",
        "Tags": [
          {
            "Key": "Name",
            "Value": "AWS::StackName"
          },
          {
            "Key": "Owner",
            "Value": "Owner"
          },
          {
            "Key": "Project",
            "Value": "Project"
          }
        ]
      }
    },
    "FileSystem": {
      "Type": "AWS::EFS::FileSystem",
      "Properties": {
        "Encrypted": true,
        "PerformanceMode": "generalPurpose"
      }
    },
    "MountTarget1": {
      "Type": "AWS::EFS::MountTarget",
      "Properties": {
        "FileSystemId": "FileSystem",
        "SubnetId": "Subnet1",
        "SecurityGroups": [
          "EfsSecurityGroup"
        ]
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Create Elastic File System"
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: Create Elastic File System
Parameters:
  Owner:
    Type: String
    Default: FirstName LastName
  Project:
    Type: String
    Default: EFS Mount
  VPC:
    Type: AWS::EC2::VPC::Id
  Subnet1:
    Type: AWS::EC2::Subnet::Id
Resources:
  FileSystem:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
      PerformanceMode: generalPurpose
  MountTarget1:
    Type: AWS::EFS::MountTarget
    Properties:
      FileSystemId: !Ref FileSystem
      SubnetId: !Ref Subnet1
      SecurityGroups:
      - !Ref EfsSecurityGroup
  EfsSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Instance to EFS Mount Access
      VpcId: !Ref VPC
      Tags:
      - Key: Name
        Value: !Ref AWS::StackName
      - Key: Owner
        Value: !Ref Owner
      - Key: Project
        Value: !Ref Project

```