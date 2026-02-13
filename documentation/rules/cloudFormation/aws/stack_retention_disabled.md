---
title: "Stack retention disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/stack_retention_disabled"
  id: "fe974ae9-858e-4991-bbd5-e040a834679f"
  display_name: "Stack retention disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Backup"
---
## Metadata

**Id:** `fe974ae9-858e-4991-bbd5-e040a834679f`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Backup

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudformation-stackset-autodeployment.html#cfn-cloudformation-stackset-autodeployment-retainstacksonaccountremoval)

### Description

StackSet AutoDeployment should be enabled and configured to retain stacks when member accounts are removed to prevent unintended deletion of stacks and their resources. Unintended deletions can remove critical security controls, logging, or IAM roles and cause service disruption.

For `AWS::CloudFormation::StackSet` resources, the `Properties.AutoDeployment` object must be present, with `Enabled` set to `true` and `RetainStacksOnAccountRemoval` set to `true`. Resources missing `AutoDeployment`, with `AutoDeployment.Enabled` set to `false`, or with `AutoDeployment.RetainStacksOnAccountRemoval` set to `false` will be flagged.

Secure configuration example:

```yaml
MyStackSet:
  Type: AWS::CloudFormation::StackSet
  Properties:
    StackSetName: my-stackset
    AutoDeployment:
      Enabled: true
      RetainStacksOnAccountRemoval: true
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  stackset:
    Type: AWS::CloudFormation::StackSet
    Properties:
      PermissionModel: SERVICE_MANAGED
      StackSetName: some_stack_name
      TemplateURL: some_stack_link
      AutoDeployment:
        Enabled: true
        RetainStacksOnAccountRemoval: true

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "stackset2": {
      "Type": "AWS::CloudFormation::Stack",
      "Properties": {
        "PermissionModel": "SERVICE_MANAGED",
        "StackSetName": "some_stack_name",
        "TemplateURL": "some_stack_link",
        "AutoDeployment": {
          "Enabled": true,
          "RetainStacksOnAccountRemoval": true
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "stackset8": {
      "Type": "AWS::CloudFormation::StackSet",
      "Properties": {
        "PermissionModel": "SERVICE_MANAGED",
        "StackSetName": "some_stack_name",
        "TemplateURL": "some_stack_link",
        "AutoDeployment": {
          "Enabled": true,
          "RetainStacksOnAccountRemoval": false
        }
      }
    },
    "stackset9": {
      "Type": "AWS::CloudFormation::StackSet",
      "Properties": {
        "PermissionModel": "SERVICE_MANAGED",
        "StackSetName": "some_stack_name",
        "TemplateURL": "some_stack_link",
        "AutoDeployment": {
          "Enabled": true
        }
      }
    },
    "stackset10": {
      "Type": "AWS::CloudFormation::StackSet",
      "Properties": {
        "PermissionModel": "SERVICE_MANAGED",
        "StackSetName": "some_stack_name",
        "TemplateURL": "some_stack_link",
        "AutoDeployment": {
          "Enabled": false,
          "RetainStacksOnAccountRemoval": false
        }
      }
    },
    "stackset11": {
      "Type": "AWS::CloudFormation::StackSet",
      "Properties": {
        "PermissionModel": "SERVICE_MANAGED",
        "StackSetName": "some_stack_name",
        "TemplateURL": "some_stack_link",
        "AutoDeployment": {
          "RetainStacksOnAccountRemoval": false
        }
      }
    },
    "stackset12": {
      "Type": "AWS::CloudFormation::StackSet",
      "Properties": {
        "PermissionModel": "SERVICE_MANAGED",
        "StackSetName": "some_stack_name",
        "TemplateURL": "some_stack_link"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  stackset3:
    Type: AWS::CloudFormation::StackSet
    Properties:
      PermissionModel: SERVICE_MANAGED
      StackSetName: some_stack_name
      TemplateURL: some_stack_link
      AutoDeployment:
        Enabled: true
        RetainStacksOnAccountRemoval: false
  stackset4:
    Type: AWS::CloudFormation::StackSet
    Properties:
      PermissionModel: SERVICE_MANAGED
      StackSetName: some_stack_name
      TemplateURL: some_stack_link
      AutoDeployment:
        Enabled: true
  stackset5:
    Type: AWS::CloudFormation::StackSet
    Properties:
      PermissionModel: SERVICE_MANAGED
      StackSetName: some_stack_name
      TemplateURL: some_stack_link
      AutoDeployment:
        Enabled: false
        RetainStacksOnAccountRemoval: true
  stackset6:
    Type: AWS::CloudFormation::StackSet
    Properties:
      PermissionModel: SERVICE_MANAGED
      StackSetName: some_stack_name
      TemplateURL: some_stack_link
      AutoDeployment:
        RetainStacksOnAccountRemoval: false
  stackset7:
    Type: AWS::CloudFormation::StackSet
    Properties:
      PermissionModel: SERVICE_MANAGED
      StackSetName: some_stack_name
      TemplateURL: some_stack_link

```