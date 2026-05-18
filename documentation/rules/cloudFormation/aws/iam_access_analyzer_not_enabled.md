---
title: "IAM Access Analyzer not enabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/iam_access_analyzer_not_enabled"
  id: "cloudformation-aws-iam-access-analyzer-not-enabled"
  display_name: "IAM Access Analyzer not enabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** {{< copyable-code >}}cloudformation-aws-iam-access-analyzer-not-enabled{{< /copyable-code >}}

**Provider:** AWS

**Platform:** CloudFormation

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://docs.amazonaws.cn/en_us/AWSCloudFormation/latest/UserGuide/aws-resource-accessanalyzer-analyzer.html)

### Description

IAM Access Analyzer provides continuous monitoring of resource-based policies to detect unintended public or cross-account access. If an `AWS::AccessAnalyzer::Analyzer` is not defined, these permission issues can go undetected, increasing the risk of data exposure or privilege escalation.
 
 The CloudFormation template must include an `AWS::AccessAnalyzer::Analyzer` resource. Templates missing this resource will be flagged. Set the `Properties.Type` to `ACCOUNT` to monitor a single account or `ORGANIZATION` to monitor an AWS Organization, and optionally provide an `AnalyzerName` for identification.

Secure configuration example:

```yaml
MyAccessAnalyzer:
  Type: AWS::AccessAnalyzer::Analyzer
  Properties:
    AnalyzerName: my-access-analyzer
    Type: ACCOUNT
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: 2010-09-09
Resources:
  Analyzer:
    Type: "AWS::AccessAnalyzer::Analyzer"
    Properties:
      AnalyzerName: MyAccountAnalyzer
      Type: ACCOUNT
      Tags:
        - Key: Kind
          Value: Dev
      ArchiveRules:
        - # Archive findings for a trusted AWS account
          RuleName: ArchiveTrustedAccountAccess
          Filter:
            - Property: "principal.AWS"
              Eq:
                - "123456789012"
        - # Archive findings for known public S3 buckets
          RuleName: ArchivePublicS3BucketsAccess
          Filter:
            - Property: "resource"
              Contains:
                - "arn:aws:s3:::docs-bucket"
                - "arn:aws:s3:::clients-bucket"

```

```json
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
      "Analyzer": {
        "Type": "AWS::AccessAnalyzer::Analyzer",
        "Properties": {
          "AnalyzerName": "MyAccountAnalyzer",
          "Type": "ACCOUNT",
          "Tags": [
            {
              "Key": "Kind",
              "Value": "Dev"
            }
          ],
          "ArchiveRules": [
            {
              "RuleName": "ArchiveTrustedAccountAccess",
              "Filter": [
                {
                  "Property": "principal.AWS",
                  "Eq": [
                    "123456789012"
                  ]
                }
              ]
            },
            {
              "RuleName": "ArchivePublicS3BucketsAccess",
              "Filter": [
                {
                  "Property": "resource",
                  "Contains": [
                    "arn:aws:s3:::docs-bucket",
                    "arn:aws:s3:::clients-bucket"
                  ]
                }
              ]
            }
          ]
        }
      }
    }
  }
```
## Non-Compliant Code Examples
```json
{
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "A sample template 2",
    "Resources": {
      "myuseeer": {
        "Type": "AWS::IAM::Group",
        "Properties": {
          "Path": "/",
          "LoginProfile": {
            "Password": "myP@ssW0rd"
          }
        }
      }
    }
  }
  
```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template 2
Resources:
  myuseeer:
    Type: AWS::IAM::Group
    Properties:
      Path: "/"
      LoginProfile:
        Password: myP@ssW0rd

```