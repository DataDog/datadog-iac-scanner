---
title: "CloudWatch IAM policy changes alarm missing"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_iam_policy_changes_alarm_missing"
  id: "eaaba502-2f94-411a-a3c2-83d63cc1776d"
  display_name: "CloudWatch IAM policy changes alarm missing"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `eaaba502-2f94-411a-a3c2-83d63cc1776d`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter#pattern)

### Description

 This check ensures that a CloudWatch log metric filter and a corresponding alarm are in place to monitor for IAM policy changes, as recommended by security best practices. If the `aws_cloudwatch_metric_alarm` resource's `metric_name` attribute does not correctly reference the log metric filter (for example, set to a placeholder such as `"XXXX NOT YOUR FILTER XXXX"` instead of `aws_cloudwatch_log_metric_filter.cis_iam_policy_change.id`), IAM policy alterations may go undetected. Without proper monitoring and alerting, unauthorized or accidental changes to IAM policies could occur without notice, potentially leading to privilege escalation or unauthorized access within your AWS environment.


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

resource "aws_cloudwatch_metric_alarm" "cis_iam_policy_change" {
  alarm_name                = "CIS-4.4-IAM-Policy-Change"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_iam_policy_change.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_iam_policy_change" {
  name           = "CIS-4.4-IAM-Policy-Change"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.4-IAM-Policy-Change"
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

resource "aws_cloudwatch_metric_alarm" "cis_iam_policy_change" {
  alarm_name                = "CIS-4.4-IAM-Policy-Change"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_iam_policy_change.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_iam_policy_change" {
  name           = "CIS-4.4-IAM-Policy-Change"
  pattern        = "{($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.4-IAM-Policy-Change"
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

resource "aws_cloudwatch_metric_alarm" "cis_iam_policy_change" {
  alarm_name                = "CIS-4.4-IAM-Policy-Change"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "XXXX NOT YOUR FILTER XXXX"
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_actions             = [aws_sns_topic.cis_alerts_sns_topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_iam_policy_change" {
  name           = "CIS-4.4-IAM-Policy-Change"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-4.4-IAM-Policy-Change"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

```