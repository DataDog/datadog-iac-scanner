---
title: "S3 bucket access to any principal"
group_id: "Ansible / AWS"
meta:
  name: "aws/s3_bucket_access_to_any_principal"
  id: "3ab1f27d-52cc-4943-af1d-43c1939e739a"
  display_name: "S3 bucket access to any principal"
  cloud_provider: "AWS"
  platform: "Ansible"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}3ab1f27d-52cc-4943-af1d-43c1939e739a{{< /copyable-code >}}

**Cloud Provider:** AWS

**Platform:** Ansible

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://docs.ansible.com/ansible/latest/collections/amazon/aws/s3_bucket_module.html#ansible-collections-amazon-aws-s3-bucket-module)

### Description

S3 bucket policies must not grant the wildcard principal (`"*"`) `Allow` access. This effectively makes the bucket accessible to any AWS account or anonymous user and can expose sensitive objects or lead to data leakage. This rule checks Ansible tasks using the `amazon.aws.s3_bucket` or `s3_bucket` modules and inspects the `policy` document to ensure no `Statement` has `Effect: "Allow"` with `Principal: "*"`.

Resources with a policy Statement where `Principal` is `*` and the effect is `Allow` are flagged. Instead, specify explicit principals (account IDs or IAM ARNs) or restrict access using conditions (for example `aws:SourceAccount` or `aws:PrincipalOrgID`) or S3 Block Public Access.

Secure example with an explicit principal:

```yaml
- name: Create S3 bucket with restricted policy
  amazon.aws.s3_bucket:
    name: my-bucket
    policy: |
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
          }
        ]
      }
```

## Compliant Code Examples
```yaml
- name: Create a simple s3 bucket with a policy
  amazon.aws.s3_bucket:
    name: mys3bucket
    policy:
      Version: '2012-10-17'
      Id: sqspolicy
      Statement:
      - Sid: First
        Effect: Deny
        Principal: '*'
        Action: '*'
        Resource: ${aws_sqs_queue.q.arn}
        Condition:
          ArnEquals:
            aws:SourceArn: ${aws_sns_topic.example.arn}

```
## Non-Compliant Code Examples
```yaml
- name: Create a simple s3 bucket with a policy
  amazon.aws.s3_bucket:
    name: mys3bucket
    policy:
      Version: "2012-10-17"
      Id: "sqspolicy"
      Statement:
      - Sid: First
        Effect: Allow
        Principal: "*"
        Action: "*"
        Resource: ${aws_sqs_queue.q.arn}
        Condition:
          ArnEquals:
            aws:SourceArn: ${aws_sns_topic.example.arn}

```