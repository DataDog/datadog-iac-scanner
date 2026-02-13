---
title: "EMR security configuration encryption disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/emr_security_configuration_encryptions_enabled"
  id: "5b033ec8-f079-4323-b5c8-99d4620433a9"
  display_name: "EMR security configuration encryption disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `5b033ec8-f079-4323-b5c8-99d4620433a9`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-emr-securityconfiguration.html)

### Description

 EMR `SecurityConfiguration` must enable encryption at rest and in transit to prevent unauthorized access to data stored on cluster disks and to protect data in flight between EMR nodes from interception.
 
 For CloudFormation, resources of type `AWS::EMR::SecurityConfiguration` must define `SecurityConfiguration.EncryptionConfiguration` with `EnableAtRestEncryption` set to `true` and `EnableInTransitEncryption` set to `true`. The `AtRestEncryptionConfiguration.LocalDiskEncryptionConfiguration.EnableEbsEncryption` property must be set to `true`, and `EncryptionKeyProviderType` must be defined. Resources missing `EncryptionConfiguration`, with any of those booleans set to `false`, or without a defined `EncryptionKeyProviderType` will be flagged.

Secure CloudFormation example:

```yaml
MyEMRSecurityConfiguration:
  Type: AWS::EMR::SecurityConfiguration
  Properties:
    SecurityConfiguration:
      EncryptionConfiguration:
        EnableAtRestEncryption: true
        EnableInTransitEncryption: true
        AtRestEncryptionConfiguration:
          LocalDiskEncryptionConfiguration:
            EnableEbsEncryption: true
            EncryptionKeyProviderType: AwsKms
```


## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
#this is a problematic code where the query should report a result(s)
Resources:
  EMRSecurityConfiguration:
    Type: AWS::EMR::SecurityConfiguration
    Properties:
       Name: String
       SecurityConfiguration:
         EncryptionConfiguration:
           EnableInTransitEncryption: true
           EnableAtRestEncryption: true
           AtRestEncryptionConfiguration:
             LocalDiskEncryptionConfiguration:
                 EnableEbsEncryption: true
                 EncryptionKeyProviderType: AwsKms
                 AwsKmsKey: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

```

```json
{
  "Resources": {
    "EMRSecurityConfiguration02": {
      "Properties": {
        "Name": "String",
        "SecurityConfiguration": {
          "EncryptionConfiguration": {
            "EnableInTransitEncryption": true,
            "EnableAtRestEncryption": true
          }
        }
      },
      "Type": "AWS::EMR::SecurityConfiguration"
    }
  }
}

```

```json
{
  "Resources": {
    "EMRSecurityConfiguration01": {
      "Type": "AWS::EMR::SecurityConfiguration",
      "Properties": {
        "Name": "String",
        "SecurityConfiguration": {
          "EncryptionConfiguration": {
            "AtRestEncryptionConfiguration": {
              "LocalDiskEncryptionConfiguration": {
                "EnableEbsEncryption": true,
                "EncryptionKeyProviderType": "AwsKms",
                "AwsKmsKey": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
              }
            }
          }
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```yaml
Resources:
  EMRSecurityConfiguration01:
    Type: AWS::EMR::SecurityConfiguration
    Properties:
       Name: String
       SecurityConfiguration:
         EncryptionConfiguration:
           AtRestEncryptionConfiguration:
             LocalDiskEncryptionConfiguration:
                 EnableEbsEncryption: false

```

```yaml
Resources:
  EMRSecurityConfiguration03:
    Type: AWS::EMR::SecurityConfiguration
    Properties:
       Name: String
       SecurityConfiguration:
         EncryptionConfiguration:
           EnableInTransitEncryption: false
           EnableAtRestEncryption: false

```

```json
{
  "Resources": {
    "EMRSecurityConfiguration": {
      "Type": "AWS::EMR::SecurityConfiguration",
      "Properties": {
        "Name": "String",
        "SecurityConfiguration": {
          "EncryptionConfiguration": {
            "EnableInTransitEncryption": false,
            "EnableAtRestEncryption": false,
            "AtRestEncryptionConfiguration": {
              "LocalDiskEncryptionConfiguration": {
                "EnableEbsEncryption": true,
                "EncryptionKeyProviderType": "AwsKms",
                "AwsKmsKey": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
              }
            }
          }
        }
      }
    }
  }
}

```