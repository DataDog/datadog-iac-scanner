---
title: "Secrets manager should specify KmsKeyId"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/secrets_manager_should_specify_kms_key_id"
  id: "c8ae9ba9-c2f7-4e5c-b32e-a4b7712d4d22"
  display_name: "Secrets manager should specify KmsKeyId"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Secret Management"
---
## Metadata

**Id:** `c8ae9ba9-c2f7-4e5c-b32e-a4b7712d4d22`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html)

### Description

 Secrets stored in AWS Secrets Manager should explicitly specify a customer-managed KMS key to ensure you control key policies, enable audited key usage, and allow cross-account access when required.

For `AWS::SecretsManager::Secret` resources, `Properties.KmsKeyId` must be defined and should reference a customer-managed KMS key (key ARN, alias, or a `Ref`/`GetAtt` to an `AWS::KMS::Key`). Omitting `KmsKeyId` causes Secrets Manager to use the AWS-managed key, which does not support granting cross-account decrypt permissions. If you need to share secrets across accounts, ensure the referenced KMS key's policy grants the necessary `kms:Decrypt` and `kms:GenerateDataKey` permissions to the target principals. Resources missing `KmsKeyId` will be flagged.

Secure configuration example:

```yaml
MyKmsKey:
  Type: AWS::KMS::Key
  Properties:
    Description: KMS key for Secrets Manager

MySecret:
  Type: AWS::SecretsManager::Secret
  Properties:
    Name: my-secret
    KmsKeyId: !Ref MyKmsKey
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
  SecretsManagerSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: String
      GenerateSecretString:
        GenerateSecretString
      KmsKeyId: String
      Name: String
      SecretString:
        String
      Tags:
        - Tag
```

```json
{
  "AWSTemplateFormatVersion": "2010-09-09T00:00:00Z",
  "Description": "A sample template",
  "Resources": {
    "SecretsManagerSecret": {
      "Type": "AWS::SecretsManager::Secret",
      "Properties": {
        "Description": "String",
        "GenerateSecretString": "GenerateSecretString",
        "KmsKeyId": "String",
        "Name": "String",
        "SecretString": "String",
        "Tags": [
          "Tag"
        ]
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
    "SecretsManagerSecret": {
      "Type": "AWS::SecretsManager::Secret",
      "Properties": {
        "Name": "String",
        "SecretString": "String",
        "Tags": [
          "Tag"
        ],
        "Description": "String",
        "GenerateSecretString": "GenerateSecretString"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: 2010-09-09
Description: A sample template
Resources:
  SecretsManagerSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: String
      GenerateSecretString:
        GenerateSecretString
      Name: String
      SecretString:
        String
      Tags:
        - Tag
```