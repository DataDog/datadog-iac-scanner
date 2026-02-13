---
title: "CloudWatch changes to NACL alarm missing"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_changes_to_nacl_alarm_missing"
  id: "0a8e8dc5-b6fc-44fc-b5a1-969ec950f9b0"
  display_name: "CloudWatch changes to NACL alarm missing"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `0a8e8dc5-b6fc-44fc-b5a1-969ec950f9b0`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter#pattern)

### Description

This check ensures that a log metric filter and an associated CloudWatch alarm are configured to monitor changes to AWS Network Access Control Lists (NACLs). Without properly linking the metric alarm to the log metric filter—such as setting the `metric_name` in `aws_cloudwatch_metric_alarm` to the correct filter like `${aws_cloudwatch_log_metric_filter.cis_changes_nacl.id}`—malicious or accidental modifications to NACLs may go undetected, increasing the risk of unauthorized network access or compromised security postures. The following example ensures the alarm triggers on relevant NACL changes and notifies security teams promptly:

```
resource "aws_cloudwatch_metric_alarm" "cis_changes_nacl" {
  metric_name = aws_cloudwatch_log_metric_filter.cis_changes_nacl.id
  // other relevant attributes...
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

resource "aws_cloudwatch_metric_alarm" "cis_changes_nacl" {
  alarm_name                = "CIS-4.11-Changes-NACL"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_changes_nacl.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_changes_nacl" {
  name           = "CIS-4.11-Changes-NACL"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.11-Changes-NACL"
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

resource "aws_cloudwatch_metric_alarm" "cis_changes_nacl" {
  alarm_name                = "CIS-4.11-Changes-NACL"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_changes_nacl.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_changes_nacl" {
  name           = "CIS-4.11-Changes-NACL"
  pattern        = "{ ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.11-Changes-NACL"
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

resource "aws_cloudwatch_metric_alarm" "cis_changes_nacl" {
  alarm_name                = "CIS-4.11-Changes-NACL"
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

resource "aws_cloudwatch_log_metric_filter" "cis_changes_nacl" {
  name           = "CIS-4.11-Changes-NACL"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.11-Changes-NACL"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

```