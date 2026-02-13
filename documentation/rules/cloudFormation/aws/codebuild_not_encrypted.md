---
title: "CodeBuild not encrypted"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/codebuild_not_encrypted"
  id: "d7467bb6-3ed1-4c82-8095-5e7a818d0aad"
  display_name: "CodeBuild not encrypted"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `d7467bb6-3ed1-4c82-8095-5e7a818d0aad`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html)

### Description

Build projects must specify an explicit AWS KMS encryption key to protect build artifacts and outputs with a customer-controlled key and retain control over key policies, rotation, and auditability.

 In CloudFormation, the `EncryptionKey` property on `AWS::CodeBuild::Project` (`Resources.<name>.Project.Properties.EncryptionKey`) must be defined and not `null`. It should reference an AWS KMS key ARN or a CloudFormation reference to an `AWS::KMS::Key`. Resources missing this property or with `EncryptionKey` set to `null` will be flagged as non-compliant.

Secure configuration example:

```yaml
MyCodeBuildProject:
  Type: AWS::CodeBuild::Project
  Properties:
    Name: my-project
    EncryptionKey: !GetAtt MyKmsKey.Arn
    # other required properties...
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
    CodeBuildProject:
      Project:
        Type: AWS::CodeBuild::Project
        Properties:
          Name: myProjectName
          Description: A description about my project
          EncryptionKey: "alias/alias-name"
          ServiceRole: !GetAtt ServiceRole.Arn
          Artifacts:
            Type: no_artifacts
          Environment:
            Type: LINUX_CONTAINER
            ComputeType: BUILD_GENERAL1_SMALL
            Image: aws/codebuild/java:openjdk-8
            EnvironmentVariables:
            - Name: varName
              Type: varType
              Value: varValue
          Source:
            Location: codebuild-demo-test/0123ab9a371ebf0187b0fe5614fbb72c
            Type: S3
          TimeoutInMinutes: 10
          Tags:
            - Key: Key1
              Value: Value1
            - Key: Key2
              Value: Value2
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "CodeBuildProject": {
      "Project": {
        "Type": "AWS::CodeBuild::Project",
        "Properties": {
          "Name": "myProjectName",
          "Description": "A description about my project",
          "TimeoutInMinutes": 10,
          "EncryptionKey": "alias/alias-name",
          "ServiceRole": "ServiceRole.Arn",
          "Artifacts": {
            "Type": "no_artifacts"
          },
          "Environment": {
            "Type": "LINUX_CONTAINER",
            "ComputeType": "BUILD_GENERAL1_SMALL",
            "Image": "aws/codebuild/java:openjdk-8",
            "EnvironmentVariables": [
              {
                "Name": "varName",
                "Type": "varType",
                "Value": "varValue"
              }
            ]
          },
          "Source": {
            "Location": "codebuild-demo-test/0123ab9a371ebf0187b0fe5614fbb72c",
            "Type": "S3"
          },
          "Tags": [
            {
              "Key": "Key1",
              "Value": "Value1"
            },
            {
              "Key": "Key2",
              "Value": "Value2"
            }
          ]
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "CodeBuildProject": {
      "Project": {
        "Type": "AWS::CodeBuild::Project",
        "Properties": {
          "Description": "A description about my project",
          "ServiceRole": "ServiceRole.Arn",
          "Artifacts": {
            "Type": "no_artifacts"
          },
          "Environment": {
            "Image": "aws/codebuild/java:openjdk-8",
            "EnvironmentVariables": [
              {
                "Name": "varName",
                "Type": "varType",
                "Value": "varValue"
              }
            ],
            "Type": "LINUX_CONTAINER",
            "ComputeType": "BUILD_GENERAL1_SMALL"
          },
          "Source": {
            "Location": "codebuild-demo-test/0123ab9a371ebf0187b0fe5614fbb72c",
            "Type": "S3"
          },
          "TimeoutInMinutes": 10,
          "Tags": [
            {
              "Key": "Key1",
              "Value": "Value1"
            },
            {
              "Key": "Key2",
              "Value": "Value2"
            }
          ],
          "Name": "myProjectName"
        }
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
    CodeBuildProject:
      Project:
        Type: AWS::CodeBuild::Project
        Properties:
          Name: myProjectName
          Description: A description about my project
          ServiceRole: !GetAtt ServiceRole.Arn
          Artifacts:
            Type: no_artifacts
          Environment:
            Type: LINUX_CONTAINER
            ComputeType: BUILD_GENERAL1_SMALL
            Image: aws/codebuild/java:openjdk-8
            EnvironmentVariables:
            - Name: varName
              Type: varType
              Value: varValue
          Source:
            Location: codebuild-demo-test/0123ab9a371ebf0187b0fe5614fbb72c
            Type: S3
          TimeoutInMinutes: 10
          Tags:
            - Key: Key1
              Value: Value1
            - Key: Key2
              Value: Value2
```