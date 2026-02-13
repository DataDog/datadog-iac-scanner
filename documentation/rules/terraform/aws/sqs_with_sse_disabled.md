---
title: "SQS with SSE disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/sqs_with_sse_disabled"
  id: "6e8849c1-3aa7-40e3-9063-b85ee300f29f"
  display_name: "SQS with SSE disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `6e8849c1-3aa7-40e3-9063-b85ee300f29f`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue)

### Description

 Amazon Simple Queue Service (SQS) queues should use Server-Side Encryption (SSE) to protect the contents of their messages while at rest. Without specifying the `kms_master_key_id` attribute in the Terraform configuration (for example, `resource "aws_sqs_queue" "positive1"`), messages sent to the queue are stored without encryption, exposing sensitive data to unauthorized access if AWS infrastructure is compromised. Enabling SSE by setting `kms_master_key_id`, as shown below, ensures that all messages are encrypted using a customer-managed key, significantly reducing the risk of data leakage.

```
resource "aws_sqs_queue" "example" {
  name                  = "terraform-example-queue"
  kms_master_key_id     = "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300
}
```


## Compliant Code Examples
```terraform
resource "aws_sqs_queue" "negative3" {
  name                    = "terraform-example-queue"
  sqs_managed_sse_enabled = true
}

```

```terraform
module "user_queue" {
  source  = "terraform-aws-modules/sqs/aws"
  version = "~> 2.0"

  name = "user"

  tags = {
    Service     = "user"
    Environment = "dev"
  }

  kms_master_key_id = "alias/aws/sqs"

}

```

```terraform
resource "aws_sqs_queue" "negative1" {
  name                              = "terraform-example-queue"
  kms_master_key_id                 = "alias/aws/sqs"
  kms_data_key_reuse_period_seconds = 300
}

```
## Non-Compliant Code Examples
```terraform
module "user_queue" {
  source  = "terraform-aws-modules/sqs/aws"
  version = "~> 2.0"

  name = "user"

  tags = {
    Service     = "user"
    Environment = "dev"
  }

  kms_master_key_id = null

}

```

```terraform
resource "aws_sqs_queue" "positive2" {
  name                              = "terraform-example-queue"
  kms_master_key_id                 = ""
  kms_data_key_reuse_period_seconds = 300
}


```

```terraform
resource "aws_sqs_queue" "positive3" {
  name                              = "terraform-example-queue"
  kms_master_key_id                 = null
  kms_data_key_reuse_period_seconds = 300
}

```