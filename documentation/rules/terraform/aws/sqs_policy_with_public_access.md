---
title: "SQS policy with public access"
group_id: "Terraform / AWS"
meta:
  name: "aws/sqs_policy_with_public_access"
  id: "730675f9-52ed-49b6-8ead-0acb5dd7df7f"
  display_name: "SQS policy with public access"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `730675f9-52ed-49b6-8ead-0acb5dd7df7f`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy)

### Description

This check looks for overly permissive `Action` statements and wildcards `"Principal": "*"` in AWS SQS queue policies, which may grant broad permissions to any user. If left unaddressed, this misconfiguration can allow unauthorized parties to perform any action on the queue, including viewing, deleting, or sending messages, which poses risks such as data leakage or denial of service. To reduce the attack surface, always scope the `Principal` attribute in policy documents to trusted AWS identities instead of using `"*"` or `{"AWS": "*"}`.

The following is an example of an insecure configuration:

```
resource "aws_sqs_queue_policy" "test" {
  ...
  policy = <<EOF
{
  "Statement": [{
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:*",
      "Resource": "arn:aws:sqs:*:111122223333:queue1"
  }]
}
EOF
}
```

A secure configuration uses a more restrictive principal, as shown below:

```
resource "aws_sqs_queue_policy" "test" {
  ...
  policy = <<EOF
{
  "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:user/TrustedUser"},
      "Action": "sqs:*",
      "Resource": "arn:aws:sqs:*:111122223333:queue1"
  }]
}
EOF
}
```

## Compliant Code Examples
```terraform
resource "aws_sqs_queue" "q" {
  name = "examplequeue"
}

resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
   "Version": "2012-10-17",
   "Id": "Queue1_Policy_UUID",
   "Statement": [{
      "Sid":"Queue1_AnonymousAccess_AllActions_AllowlistIP",
      "Effect": "Allow",
      "Principal": "SOMETHING",
      "Action": "sqs:*",
      "Resource": "arn:aws:sqs:*:111122223333:queue1",
      "Condition" : {
         "IpAddress" : {
            "aws:SourceIp":"192.168.143.0/24"
         }
      }
   }]
}
POLICY
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_sqs_queue" "q" {
  name = "examplequeue"
}

resource "aws_sqs_queue_policy" "test" {
  queue_url = aws_sqs_queue.q.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Id": "Queue1_Policy_UUID",
  "Statement": [{
      "Sid":"Queue1_AnonymousAccess_AllActions_AllowlistIP",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:*",
      "Resource": "arn:aws:sqs:*:111122223333:queue1",
      "Condition" : {
        "IpAddress" : {
            "aws:SourceIp":"192.168.143.0/24"
        }
      }
  }]
}
EOF
}

resource "aws_sqs_queue" "q_aws_array" {
  name = "examplequeue_aws_array"
}

resource "aws_sqs_queue" "q_aws" {
  name = "examplequeue_aws"
}

resource "aws_sqs_queue_policy" "test_aws" {
  queue_url = aws_sqs_queue.q_aws.id

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Id": "Queue1_Policy_UUID",
   "Statement": [{
      "Sid":"Queue1_AnonymousAccess_AllActions_AllowlistIP",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "sqs:*",
      "Resource": "arn:aws:sqs:*:111122223333:queue1",
      "Condition" : {
         "IpAddress" : {
            "aws:SourceIp":"192.168.143.0/24"
         }
      }
   }]
}
EOF
}

resource "aws_sqs_queue_policy" "test_aws_array" {
  queue_url = aws_sqs_queue.q_aws_array.id

  policy = <<EOF
{
   "Version": "2012-10-17",
   "Id": "Queue1_Policy_UUID",
   "Statement": [{
      "Sid":"Queue1_AnonymousAccess_AllActions_AllowlistIP",
      "Effect": "Allow",
      "Principal": {
        "AWS": ["*"]
      },
      "Action": "sqs:*",
      "Resource": "arn:aws:sqs:*:111122223333:queue1",
      "Condition" : {
         "IpAddress" : {
            "aws:SourceIp":"192.168.143.0/24"
         }
      }
   }]
}
EOF
}

```