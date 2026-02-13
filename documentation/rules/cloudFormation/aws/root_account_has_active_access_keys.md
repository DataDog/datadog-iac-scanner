---
title: "Root account has active access keys"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/root_account_has_active_access_keys"
  id: "4c137350-7307-4803-8c04-17c09a7a9fcf"
  display_name: "Root account has active access keys"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `4c137350-7307-4803-8c04-17c09a7a9fcf`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html)

### Description

 Access keys associated with the AWS root account grant persistent, account-wide credentials. If compromised, they can lead to full account takeover and loss of control over all resources.

In CloudFormation, `AWS::IAM::AccessKey` resources must not be associated with the root account. This rule flags `Resources.<name>.Properties.UserName` values that contain `root` (case-insensitive). Instead of creating or using root access keys, delete or deactivate any existing root keys, enable MFA on the root account, and provision IAM users or roles with least privilege for programmatic access.

Secure configuration example (associate access keys with an IAM user rather than the root account):

```yaml
MyUser:
  Type: AWS::IAM::User
  Properties:
    UserName: app-user

MyAccessKey:
  Type: AWS::IAM::AccessKey
  Properties:
    UserName: !Ref MyUser
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  CFNKeys:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: MyUser

```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "CFNKeys": {
      "Type": "AWS::IAM::AccessKey",
      "Properties": {
        "UserName": "MyUser"
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
    "CFNKeys": {
      "Type": "AWS::IAM::AccessKey",
      "Properties": {
        "UserName": "Root"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  CFNKeys:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: Root

```