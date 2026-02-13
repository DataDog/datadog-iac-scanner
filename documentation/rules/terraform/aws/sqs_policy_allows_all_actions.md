---
title: "SQS policy allows all actions"
group_id: "Terraform / AWS"
meta:
  name: "aws/sqs_policy_allows_all_actions"
  id: "816ea8cf-d589-442d-a917-2dd0ce0e45e3"
  display_name: "SQS policy allows all actions"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `816ea8cf-d589-442d-a917-2dd0ce0e45e3`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy)

### Description

 When SQS policies use the wildcard (`*`) for actions, they grant excessive permissions that violate the principle of least privilege, potentially allowing unauthorized entities to perform any operation on the queue. This vulnerability creates a significant security risk where attackers could read sensitive messages, delete messages, or modify queue configurations if they gain access. To avoid excessive permissions, replace wildcards with specific actions, such as `"Action": "sqs:SendMessage"` instead of the insecure `"Action": "*"`.


## Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  versioning = {
    enabled = true
  }

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.q.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${aws_sns_topic.example.arn}"
        }
      }
    }
  ]
}
POLICY

   server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

```

```terraform
resource "aws_sqs_queue" "negative1" {
  name = "examplequeue"
}

resource "aws_sqs_queue_policy" "negative2" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.q.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${aws_sns_topic.example.arn}"
        }
      }
    }
  ]
}
POLICY
}
```
## Non-Compliant Code Examples
```terraform
module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  versioning = {
    enabled = true
  }

  policy = <<POLICY
    {
      "Version": "2012-10-17",
      "Id": "sqspolicy",
      "Statement": [
        {
          "Sid": "First",
          "Effect": "Allow",
          "Principal": "*",
          "Action": "*",
          "Resource": "${aws_sqs_queue.q.arn}",
          "Condition": {
            "ArnEquals": {
              "aws:SourceArn": "${aws_sns_topic.example.arn}"
            }
          }
        }
      ]
    }
  POLICY

   server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

```

```terraform
resource "aws_sqs_queue" "positive1" {
  name = "examplequeue"
}

resource "aws_sqs_queue_policy" "positive2" {
  queue_url = aws_sqs_queue.q.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*",
      "Resource": "${aws_sqs_queue.q.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${aws_sns_topic.example.arn}"
        }
      }
    }
  ]
}
POLICY
}
```