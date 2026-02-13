---
title: "DynamoDB table not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/dynamodb_table_not_encrypted"
  id: "ce089fd4-1406-47bd-8aad-c259772bb294"
  display_name: "DynamoDB table not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `ce089fd4-1406-47bd-8aad-c259772bb294`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dynamodb_table#server_side_encryption)

### Description

 This check verifies if AWS DynamoDB Tables are configured with server-side encryption to protect sensitive data at rest. Without encryption, stored data is vulnerable to unauthorized access if the database storage is compromised. To properly secure your DynamoDB table, you must include a `server_side_encryption` block with `enabled = true`, as shown below:

```
server_side_encryption {
  enabled = true
}
```


## Compliant Code Examples
```terraform
resource "aws_dynamodb_table" "example" {
  name             = "example"
  hash_key         = "TestTableHashKey"
  billing_mode     = "PAY_PER_REQUEST"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  server_side_encryption {
    enabled = true
  }

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

  replica {
    region_name = "us-east-2"
  }

  replica {
    region_name = "us-west-2"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_dynamodb_table" "example" {
  name             = "example"
  hash_key         = "TestTableHashKey"
  billing_mode     = "PAY_PER_REQUEST"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

  replica {
    region_name = "us-east-2"
  }

  replica {
    region_name = "us-west-2"
  }
}

resource "aws_dynamodb_table" "example_2" {
  name             = "example"
  hash_key         = "TestTableHashKey"
  billing_mode     = "PAY_PER_REQUEST"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  server_side_encryption {
    enabled = false
  }

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

  replica {
    region_name = "us-east-2"
  }

  replica {
    region_name = "us-west-2"
  }
}

```