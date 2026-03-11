---
title: "SES Policy With Allowed IAM Actions"
group_id: "Ansible / AWS"
meta:
  name: "aws/ses_policy_with_allowed_iam_actions"
  id: "8ed0bfce-f780-46d4-b086-21c3628f09ad"
  display_name: "SES Policy With Allowed IAM Actions"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `8ed0bfce-f780-46d4-b086-21c3628f09ad`

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/community/aws/aws_ses_identity_policy_module.html#parameter-policy)

### Description

SES identity policies must not grant Allow permissions for all actions to all principals, because a wildcard Action ('*') combined with a wildcard Principal ('*') lets any actor perform any API operation on the identity, enabling email spoofing, unauthorized sending, and potential privilege escalation. Check Ansible resources of type `community.aws.aws_ses_identity_policy` and `aws.aws_ses_identity_policy`; the `policy` document must not contain statements with `"Effect": "Allow"` where `Action` is `"*"` (or contains `"*"`) and `Principal` is a wildcard (for example `"*"` or `{"AWS":"*"}`). Resources with such statements will be flagged; instead, specify explicit principals (AWS account ARNs or service principals) and restrict `Action` to the minimum required SES API operations. Secure example showing a restricted policy:

```yaml
- name: Attach SES identity policy
  community.aws.aws_ses_identity_policy:
    identity: "example.com"
    policy: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
            "Action": [ "ses:SendEmail", "ses:SendRawEmail" ],
            "Resource": "arn:aws:ses:us-east-1:123456789012:identity/example.com"
          }
        ]
      }
```

## Compliant Code Examples
```yaml
- name: add sending authorization policy to email identity2
  community.aws.aws_ses_identity_policy:
    identity: example@example.com
    policy_name: ExamplePolicy
    policy: >
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "*",
            "Principal": {
              "AWS": "arn:aws:iam::987654321145:root"
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": ""
          }
        ]
      }
    state: present

```
## Non-Compliant Code Examples
```yaml
- name: add sending authorization policy to email identityyy
  community.aws.aws_ses_identity_policy:
    identity: example@example.com
    policy_name: ExamplePolicy
    policy: >
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "*",
            "Principal": {
              "AWS": "*"
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": ""
          }
        ]
      }
    state: present

```