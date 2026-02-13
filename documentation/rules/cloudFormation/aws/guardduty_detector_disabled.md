---
title: "GuardDuty detector disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/guardduty_detector_disabled"
  id: "a25cd877-375c-4121-a640-730929936fac"
  display_name: "GuardDuty detector disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `a25cd877-375c-4121-a640-730929936fac`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-guardduty-detector.html)

### Description

 Amazon GuardDuty must be enabled to provide continuous threat detection and alerting. Disabling it can allow malicious activity to go undetected and delay incident response.
 
 The `Enable` property on `AWS::GuardDuty::Detector` resources must be set to `true`. This rule flags `AWS::GuardDuty::Detector` resources where `Enable` is explicitly set to `false`.

Secure configuration example:

```yaml
MyDetector:
  Type: AWS::GuardDuty::Detector
  Properties:
    Enable: true
```


## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
    mydetector:
      Type: AWS::GuardDuty::Detector
      Properties:
          Enable: True
          FindingPublishingFrequency: FIFTEEN_MINUTES

```

```json
{
  "document": [
    {
      "AWSTemplateFormatVersion": "2010-09-09",
      "Resources": {
        "mydetector2": {
          "Properties": {
            "Enable": true,
            "FindingPublishingFrequency": "FIFTEEN_MINUTES"
          },
          "Type": "AWS::GuardDuty::Detector"
        }
      },
      "id": "f63e21c6-c58e-45cf-b7b4-6b548d9f7674",
      "file": "C:\\Users\\foo\\Desktop\\Data\\yaml\\yaml.yaml"
    }
  ]
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "mydetector4": {
      "Properties": {
        "Enable": false,
        "FindingPublishingFrequency": "FIFTEEN_MINUTES"
      },
      "Type": "AWS::GuardDuty::Detector"
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  mydetector3:
    Type: AWS::GuardDuty::Detector
    Properties:
        Enable: False
        FindingPublishingFrequency: FIFTEEN_MINUTES

```