---
title: "SNS topic is publicly accessible"
group_id: "Ansible / AWS"
meta:
  name: "aws/sns_topic_is_publicly_accessible"
  id: "905f4741-f965-45c1-98db-f7a00a0e5c73"
  display_name: "SNS topic is publicly accessible"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}905f4741-f965-45c1-98db-f7a00a0e5c73{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/sns_topic_module.html)

### Description

SNS topic policies must not allow any principal (`*`). Making a topic public permits unauthorized publishing or subscription, which can lead to message injection, data exfiltration, or unintended triggering of downstream systems.

In Ansible tasks using the `community.aws.sns_topic` or `sns_topic` modules, check the `policy` property and flag any `Statement` with `"Effect": "Allow"` where `Principal` is the wildcard (`"*"`) or contains `"AWS": "*"`. Policy statements must instead specify explicit principals such as AWS account IDs, ARNs, or service principals. Statements that use a wildcard principal or are not limited to a specific account ID are flagged.

Secure configuration example for an Ansible task (explicit principal):

```yaml
- name: create sns topic with restricted policy
  community.aws.sns_topic:
    name: my-topic
    policy:
      Version: "2012-10-17"
      Statement:
        - Sid: AllowSpecificAccount
          Effect: Allow
          Principal:
            AWS: "arn:aws:iam::123456789012:root"
          Action: "SNS:Publish"
          Resource: "arn:aws:sns:us-east-1:123456789012:my-topic"
```

## Compliant Code Examples
```yaml
- name: Create alarm SNS topic community
  community.aws.sns_topic:
    name: alarms
    state: present
    display_name: alarm SNS topic
    delivery_policy:
      http:
        defaultHealthyRetryPolicy:
          minDelayTarget: 2
          maxDelayTarget: 4
          numRetries: 3
          numMaxDelayRetries: 5
          backoffFunction: <linear|arithmetic|geometric|exponential>
        disableSubscriptionOverrides: true
        defaultThrottlePolicy:
          maxReceivesPerSecond: 10
    policy:
      Version: '2022-05-02'
      Statement:
      - Effect: Allow
        Action: Publish
        Principal: NotAll

- name: Create alarm SNS topic
  sns_topic:
    name: alarms
    state: present
    display_name: alarm SNS topic
    delivery_policy:
      http:
        defaultHealthyRetryPolicy:
          minDelayTarget: 2
          maxDelayTarget: 4
          numRetries: 3
          numMaxDelayRetries: 5
          backoffFunction: <linear|arithmetic|geometric|exponential>
        disableSubscriptionOverrides: true
        defaultThrottlePolicy:
          maxReceivesPerSecond: 10
    policy:
      Version: '2022-05-02'
      Statement:
      - Effect: Allow
        Action: Publish
        Principal: NotAll

# Principal "*" but limited to account ID via Condition - should NOT be flagged (is_access_limited_to_an_account_id)
- name: SNS topic with star principal but aws:SourceAccount condition
  community.aws.sns_topic:
    name: account-scoped-topic
    state: present
    policy:
      Version: '2012-10-17'
      Statement:
      - Effect: Allow
        Action: sns:Publish
        Principal: "*"
        Resource: "*"
        Condition:
          StringEquals:
            aws:SourceAccount: "123456789012"

```
## Non-Compliant Code Examples
```yaml
---
- name: Create alarm SNS topic community
  community.aws.sns_topic:
    name: "alarms"
    state: present
    display_name: "alarm SNS topic"
    delivery_policy:
      http:
        defaultHealthyRetryPolicy:
          minDelayTarget: 2
          maxDelayTarget: 4
          numRetries: 3
          numMaxDelayRetries: 5
          backoffFunction: "<linear|arithmetic|geometric|exponential>"
        disableSubscriptionOverrides: True
        defaultThrottlePolicy:
          maxReceivesPerSecond: 10
    subscriptions:
      - endpoint: "my_email_address@example.com"
        protocol: "email"
      - endpoint: "my_mobile_number"
        protocol: "sms"
    policy:
      Version: '2022-05-02'
      Statement:
        - Action: Publish
          Effect: Allow
          Principal: "*"
- name: Create alarm SNS topic
  sns_topic:
    name: "alarms"
    state: present
    display_name: "alarm SNS topic"
    delivery_policy:
      http:
        defaultHealthyRetryPolicy:
          minDelayTarget: 2
          maxDelayTarget: 4
          numRetries: 3
          numMaxDelayRetries: 5
          backoffFunction: "<linear|arithmetic|geometric|exponential>"
        disableSubscriptionOverrides: True
        defaultThrottlePolicy:
          maxReceivesPerSecond: 10
    subscriptions:
      - endpoint: "my_email_address@example.com"
        protocol: "email"
      - endpoint: "my_mobile_number"
        protocol: "sms"
    policy:
      Version: '2022-05-02'
      Statement:
        - Effect: Allow
          Action: Publish
          Principal: '*'

```