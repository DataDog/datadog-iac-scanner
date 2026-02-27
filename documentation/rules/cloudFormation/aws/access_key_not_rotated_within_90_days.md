---
title: "High access key rotation period"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/access_key_not_rotated_within_90_days"
  id: "800fa019-49dd-421b-9042-7331fdd83fa2"
  display_name: "High access key rotation period"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `800fa019-49dd-421b-9042-7331fdd83fa2`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://docs.amazonaws.cn/en_us/config/latest/developerguide/access-keys-rotated.html)

### Description

IAM access keys must be rotated regularly to reduce the risk from long-lived credentials and limit the exposure window if a key is compromised. Ensure an `AWS::Config::ConfigRule` resource exists with `Source.SourceIdentifier` set to `ACCESS_KEYS_ROTATED` and that its `InputParameters` contain a `maxAccessKeyAge` value less than or equal to `90` (days). Resources missing this ConfigRule, missing `InputParameters`, or with `maxAccessKeyAge` > `90` will be flagged; `maxAccessKeyAge` is evaluated numerically and is often provided as a string.

Secure configuration example (CloudFormation):

```yaml
AccessKeyRotationRule:
  Type: AWS::Config::ConfigRule
  Properties:
    ConfigRuleName: enforce-access-key-rotation
    Source:
      Owner: AWS
      SourceIdentifier: ACCESS_KEYS_ROTATED
    InputParameters: '{"maxAccessKeyAge":"90"}'
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
        SourceIdentifier: ACCESS_KEYS_ROTATED
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
          "SourceIdentifier": "ACCESS_KEYS_ROTATED",
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