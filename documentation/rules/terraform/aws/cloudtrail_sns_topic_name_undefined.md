---
title: "CloudTrail SNS topic name undefined"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudtrail_sns_topic_name_undefined"
  id: "482b7d26-0bdb-4b5f-bf6f-545826c0a3dd"
  display_name: "CloudTrail SNS topic name undefined"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `482b7d26-0bdb-4b5f-bf6f-545826c0a3dd`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail)

### Description

 This check verifies whether an Amazon CloudTrail resource is configured to send logs to an SNS topic by setting the `sns_topic_name` attribute. Without specifying `sns_topic_name`, CloudTrail will not publish notifications of log file delivery events to Amazon SNS, which could result in missed alerts or delayed incident response. To address this, you should configure CloudTrail with an SNS topic, as shown below:

```
resource "aws_cloudtrail" "example" {
  // ... other configuration ...
  sns_topic_name = "some-topic"
}
```


## Compliant Code Examples
```terraform
resource "aws_cloudtrail" "negative1" {
  # ... other configuration ...

  sns_topic_name = "some-topic"
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudtrail" "positive1" {
  # ... other configuration ...
}

resource "aws_cloudtrail" "positive2" {
  # ... other configuration ...

  sns_topic_name = null
}
```