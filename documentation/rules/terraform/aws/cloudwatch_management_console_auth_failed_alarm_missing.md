---
title: "CloudWatch management console auth failed alarm missing"
group_id: "Terraform / AWS"
meta:
  name: "aws/cloudwatch_management_console_auth_failed_alarm_missing"
  id: "5864d189-ee9a-4009-ac0c-8a582e6b7919"
  display_name: "CloudWatch management console auth failed alarm missing"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `5864d189-ee9a-4009-ac0c-8a582e6b7919`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter#pattern)

### Description

This check ensures that a CloudWatch log metric filter and corresponding alarm are properly configured to monitor AWS Management Console authentication failures. Without a correct association between the metric alarm (`aws_cloudwatch_metric_alarm.metric_name`) and the log metric filter (for example, `aws_cloudwatch_metric_filter.cis_console_authn_failure_metric_filter.id`), failed login events may go undetected, leaving the environment vulnerable to brute-force attacks or unauthorized access attempts. A secure Terraform configuration links the alarm to the appropriate metric filter, as shown below:

```
metric_name = aws_cloudwatch_log_metric_filter.cis_console_authn_failure_metric_filter.id
```

This enables timely alerting on suspicious authentication failures, reducing the risk of compromised credentials going unnoticed.

## Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_console_authn_failure_metric_filter" {
  name           = "CIS-ConsoleAuthenticationFailure"
  pattern        = "{ (($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\")) }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-ConsoleAuthenticationFailure"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "cis_console_authn_failure_cw_alarm" {
  alarm_name                = "CIS-3.6-ConsoleAuthenticationFailure"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_console_authn_failure_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "cis_no_mfa_console_signin_metric_filter" {
  name           = "CIS-ConsoleSigninWithoutMFA"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
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
  alarm_actions             = ["aws_sns_topic.CIS_Alerts_SNS_Topic.arn"]
  insufficient_data_actions = []
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_console_authn_failure_metric_filter" {
  name           = "CIS-ConsoleAuthenticationFailure"
  pattern        = "{ (($.eventName = ConsoleLogin)) && ($.errorMessage != \"Failed authentication\") }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-ConsoleAuthenticationFailure"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "cis_console_authn_failure_cw_alarm" {
  alarm_name                = "CIS-3.6-ConsoleAuthenticationFailure"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_console_authn_failure_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

```

```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_console_authn_failure_metric_filter" {
  name           = "CIS-ConsoleAuthenticationFailure"
  pattern        = "{ $.eventName != ConsoleLogin && $.errorMessage = \"Failed authentication\" }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-ConsoleAuthenticationFailure"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_console_authn_failure_cw_alarm" {
  alarm_name                = "CIS-3.6-ConsoleAuthenticationFailure"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_console_authn_failure_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

```

```terraform
resource "aws_cloudwatch_log_metric_filter" "cis_console_authn_failure_metric_filter" {
  name           = "CIS-ConsoleAuthenticationFailure"
  pattern        = "{ $.eventName = ConsoleLogin || $.errorMessage = \"Failed authentication\" }"
  log_group_name = aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name

  metric_transformation {
    name      = "CIS-ConsoleAuthenticationFailure"
    namespace = "CIS_Metric_Alarm_Namespace"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_console_authn_failure_cw_alarm" {
  alarm_name                = "CIS-3.6-ConsoleAuthenticationFailure"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cis_console_authn_failure_metric_filter.id
  namespace                 = "CIS_Metric_Alarm_Namespace"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [aws_sns_topic.CIS_Alerts_SNS_Topic.arn]
  insufficient_data_actions = []
}

```