---
title: "Config rule for encrypted volumes disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/config_rule_for_encryption_volumes_disabled"
  id: "1b6322d9-c755-4f8c-b804-32c19250f2d9"
  display_name: "Config rule for encrypted volumes disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `1b6322d9-c755-4f8c-b804-32c19250f2d9`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-config-configrule.html#cfn-config-configrule-source)

### Description

 AWS Config should include the managed rule that detects unencrypted EBS volumes so that unencrypted volumes, snapshots, and backups are identified and remediated to prevent data exposure if storage media or snapshots are compromised.

 This check looks for an `AWS::Config::ConfigRule` resource with `Properties.Source.SourceIdentifier` set to `ENCRYPTED_VOLUMES`. Resources missing this config rule or with a different `SourceIdentifier` will be flagged.

 Ensure a config rule with `SourceIdentifier` set to `ENCRYPTED_VOLUMES` (typically `Owner` set to `AWS` for the managed rule) is defined and enabled in your CloudFormation template.

Secure CloudFormation example:

```yaml
EncryptedVolumesConfigRule:
  Type: AWS::Config::ConfigRule
  Properties:
    ConfigRuleName: encrypted-volumes
    Source:
      Owner: AWS
      SourceIdentifier: ENCRYPTED_VOLUMES
```


## Compliant Code Examples
```yaml
Resources:
  ConfigRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: access-keys-rotated
      InputParameters:
        maxAccessKeyAge: 90
      Source:
        Owner: AWS
        SourceIdentifier: ENCRYPTED_VOLUMES
      MaximumExecutionFrequency: TwentyFour_Hours


```

```json
{
  "Resources": {
    "ConfigRule": {
      "Type": "AWS::Config::ConfigRule",
      "Properties": {
        "MaximumExecutionFrequency": "TwentyFour_Hours",
        "ConfigRuleName": "access-keys-rotated",
        "InputParameters": {
          "maxAccessKeyAge": 90
        },
        "Source": {
          "SourceIdentifier": "ENCRYPTED_VOLUMES",
          "Owner": "AWS"
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```json
{
  "Resources": {
    "ConfigRule": {
      "Type": "AWS::Config::ConfigRule",
      "Properties": {
        "ConfigRuleName": "access-keys-rotated",
        "InputParameters": {
          "maxAccessKeyAge": 100
        },
        "Source": {
          "Owner": "AWS",
          "SourceIdentifier": "ACCESS_KEYS_ROTATED"
        },
        "MaximumExecutionFrequency": "TwentyFour_Hours"
      }
    }
  }
}

```

```yaml
Resources:
  ConfigRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: access-keys-rotated
      InputParameters:
        maxAccessKeyAge: 100
      Source:
        Owner: AWS
        SourceIdentifier: ACCESS_KEYS_ROTATED
      MaximumExecutionFrequency: TwentyFour_Hours


```