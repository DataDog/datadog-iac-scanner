---
title: "CloudWatch logging disabled"
group_id: "CloudFormation / AWS"
meta:
  name: "aws/cloudwatch_logging_disabled"
  id: "0f0fb06b-0f2f-4374-8588-f2c7c348c7a0"
  display_name: "CloudWatch logging disabled"
  cloud_provider: "AWS"
  platform: "CloudFormation"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `0f0fb06b-0f2f-4374-8588-f2c7c348c7a0`

**Cloud Provider:** AWS

**Platform:** CloudFormation

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-route53-hostedzone.html#cfn-route53-hostedzone-queryloggingconfig)

### Description

Route 53 hosted zones should have query logging enabled so DNS queries are recorded for detection, forensics, and troubleshooting. Without query logs, DNS-based attacks and misconfigurations are harder to detect and investigate.

 In CloudFormation, `AWS::Route53::HostedZone` resources must include the `QueryLoggingConfig` property with a valid `CloudWatchLogsLogGroupArn` pointing to a CloudWatch Logs log group to receive DNS query logs. Ensure the referenced log group exists and that permissions allow Route 53 to publish logs. Resources missing `QueryLoggingConfig` will be flagged.

Secure configuration example:

```yaml
MyHostedZone:
  Type: AWS::Route53::HostedZone
  Properties:
    Name: example.com
    QueryLoggingConfig:
      CloudWatchLogsLogGroupArn: arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/example
```

## Compliant Code Examples
```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  HostedZone:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: "HostedZone"
      QueryLoggingConfig:
        CloudWatchLogsLogGroupArn: "SomeCloudWatchLogGroupArn"

```

```json
{
  "Description": "Router53",
  "Resources": {
    "HostedZone2": {
      "Type": "AWS::Route53::HostedZone",
      "Properties": {
        "Name": "HostedZone",
        "QueryLoggingConfig": {
          "CloudWatchLogsLogGroupArn": "SomeCloudWatchLogGroupArn"
        }
      }
    }
  },
  "AWSTemplateFormatVersion": "2010-09-09"
}

```
## Non-Compliant Code Examples
```json
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Description": "Router53",
  "Resources": {
    "HostedZone4": {
      "Type": "AWS::Route53::HostedZone",
      "Properties": {
        "Name": "HostedZone"
      }
    }
  }
}

```

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: "Router53"
Resources:
  HostedZone3:
    Type: AWS::Route53::HostedZone
    Properties:
      Name: "HostedZone"

```