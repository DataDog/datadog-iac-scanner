---
title: "CloudWatch disabling or scheduled deletion of customer created CMK alarm missing"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_disabling_or_scheduled_deletion_of_customer_created_cmk_alarm_missing"
  id: "56a585f5-555c-48b2-8395-e64e4740a9cf"
  display_name: "CloudWatch disabling or scheduled deletion of customer created CMK alarm missing"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `56a585f5-555c-48b2-8395-e64e4740a9cf`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter#pattern)

### Description

 A log metric filter and corresponding alarm should be in place to detect when a customer master key (CMK) in AWS KMS is disabled or scheduled for deletion, as these actions may indicate unauthorized or risky changes to encryption controls. Without proper alerting, malicious or accidental actions targeting CMKs may go unnoticed, putting sensitive encrypted data at risk of compromise or loss. A secure Terraform example ensures the `aws_cloudwatch_metric_alarm` uses the metric created by the `aws_cloudwatch_log_metric_filter` to trigger alerts:

```
resource "aws_cloudwatch_metric_alarm" "disable_delete_cmk" {
  metric_name  = aws_cloudwatch_log_metric_filter.disable_delete_cmk.id
  // other attributes...
}
```


## Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-2"
}

resource "aws_cloudwatch_log_group" "CIS_CloudWatch_LogsGroup" {
  name = "CIS_CloudWatch_LogsGroup"
}

resource "aws_sns_topic" "cis_alerts_sns_topic" {
  name = "cis-alerts-sns-topic"
}

resource "aws_cloudwatch_metric_alarm" "cis_disable_delete_cmk" {
  alarm_name                = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_disable_delete_cmk.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_disable_delete_cmk" {
  name           = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  pattern        = "{ ($.eventSource = \"kms.amazonaws.com\") && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.7-Disable-Scheduled-Delete-CMK"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-2"
}

resource "aws_cloudwatch_log_group" "CIS_CloudWatch_LogsGroup" {
  name = "CIS_CloudWatch_LogsGroup"
}

resource "aws_sns_topic" "cis_alerts_sns_topic" {
  name = "cis-alerts-sns-topic"
}

resource "aws_cloudwatch_metric_alarm" "cis_disable_delete_cmk" {
  alarm_name                = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_disable_delete_cmk.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_disable_delete_cmk" {
  name           = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  pattern        = "{ ($.eventSource = \"kms.amazonaws.com\") || (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.7-Disable-Scheduled-Delete-CMK"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

```

```terraform
provider "aws" {
  region = "us-east-2"
}

resource "aws_cloudwatch_log_group" "CIS_CloudWatch_LogsGroup" {
  name = "CIS_CloudWatch_LogsGroup"
}

resource "aws_sns_topic" "cis_alerts_sns_topic" {
  name = "cis-alerts-sns-topic"
}

resource "aws_cloudwatch_metric_alarm" "cis_disable_delete_cmk" {
  alarm_name                = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_disable_delete_cmk.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_disable_delete_cmk" {
  name           = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  pattern        = "{ ($.eventSource = \"kms.amazonaws.com\") && (($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.7-Disable-Scheduled-Delete-CMK"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

```

```terraform
provider "aws" {
  region = "us-east-2"
}

resource "aws_cloudwatch_log_group" "CIS_CloudWatch_LogsGroup" {
  name = "CIS_CloudWatch_LogsGroup"
}

resource "aws_sns_topic" "cis_alerts_sns_topic" {
  name = "cis-alerts-sns-topic"
}

resource "aws_cloudwatch_metric_alarm" "cis_disable_delete_cmk" {
  alarm_name                = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "OTHER FILTER"
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_disable_delete_cmk" {
  name           = "CIS-4.7-Disable-Scheduled-Delete-CMK"
  pattern        = "{ ($.eventSource = \"kms.amazonaws.com\") && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.7-Disable-Scheduled-Delete-CMK"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

```