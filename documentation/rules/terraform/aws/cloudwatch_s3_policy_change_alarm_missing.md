---
title: "CloudWatch S3 policy change alarm missing"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_s3_policy_change_alarm_missing"
  id: "27c6a499-895a-4dc7-9617-5c485218db13"
  display_name: "CloudWatch S3 policy change alarm missing"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `27c6a499-895a-4dc7-9617-5c485218db13`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter#pattern)

### Description

This check ensures that a CloudWatch log metric filter and corresponding alarm are in place to monitor S3 bucket policy changes, such as modifications to ACLs or bucket policies. Without the correct configuration, unauthorized changes to S3 bucket permissions could go unnoticed, increasing the risk of data exposure or policy misconfiguration. For example, `aws_cloudwatch_metric_alarm` should reference the correct metric filter, as shown below, to promptly alert on policy changes and help reduce the time to detect and respond to potentially dangerous modifications.

```
metric_name = aws_cloudwatch_log_metric_filter.cis_s3_bucket_policy_change_metric_filter.id
```

## Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_s3_bucket_policy_change_metric_filter" {
  name           = "CIS-S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-S3BucketPolicyChanges"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_s3_bucket_policy_change_cw_alarm" {
  alarm_name                = "CIS-3.8-S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_s3_bucket_policy_change_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_no_mfa_console_signin_metric_filter" {
  name           = "CIS-ConsoleSigninWithoutMFA"
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-ConsoleSigninWithoutMFA"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_no_mfa_console_signin_cw_alarm" {
  alarm_name                = "CIS-3.2-ConsoleSigninWithoutMFA"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_no_mfa_console_signin_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_s3_bucket_policy_change_metric_filter" {
  name           = "CIS-S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && (($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-S3BucketPolicyChanges"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_S3_Bucket_Policy_Change_CW_Alarm" {
  alarm_name                = "CIS-3.8-S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_s3_bucket_policy_change_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

```

```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_s3_bucket_policy_change_metric_filter" {
  name           = "CIS-S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\") && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-S3BucketPolicyChanges"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_S3_Bucket_Policy_Change_CW_Alarm" {
  alarm_name                = "CIS-3.8-S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_s3_bucket_policy_change_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

```

```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_s3_bucket_policy_change_metric_filter" {
  name           = "CIS-S3BucketPolicyChanges"
  pattern        = "{ $.eventSource = \"s3.amazonaws.com\" }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-S3BucketPolicyChanges"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_S3_Bucket_Policy_Change_CW_Alarm" {
  alarm_name                = "CIS-3.8-S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_s3_bucket_policy_change_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

```