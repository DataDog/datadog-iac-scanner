---
title: "Hardcoded AWS access key in Lambda"
group_id: "Terraform / AWS"
meta:
  name: "aws/hardcoded_aws_access_key_in_lambda"
  id: "1402afd8-a95c-4e84-8b0b-6fb43758e6ce"
  display_name: "Hardcoded AWS access key in Lambda"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Secret Management"
---
## Metadata

**Id:** `1402afd8-a95c-4e84-8b0b-6fb43758e6ce`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function)

### Description

 Hardcoding AWS access keys in Lambda function environment variables poses a significant security risk as they can be exposed through version control systems, logs, or to anyone with access to the infrastructure code. If these credentials are compromised, attackers can gain unauthorized access to AWS resources, potentially leading to data breaches, resource manipulation, or service disruption. Instead of hardcoding access keys like `foo = "AKIAIOSFODNN7EXAMAAA"`, use a secure approach by either referencing AWS IAM roles that grant the necessary permissions to your Lambda function or storing sensitive credentials in AWS Secrets Manager or Parameter Store and retrieving them at runtime, as shown in the secure example: `foo = "test"`.


## Compliant Code Examples
```terraform
resource "aws_iam_role" "negative1" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_lambda_function" "negative2" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_name"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "exports.test"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs12.x"

  environment {
    variables = {
      foo = "test"
    }
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_iam_role" "positive1" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_lambda_function" "positive2" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_name"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "exports.test"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs12.x"

  environment {
    variables = {
      foo = "AKIAIOSFODNN7EXAMAAA"
    }
  }
}


resource "aws_lambda_function" "positive3" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_name"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "exports.test"

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs12.x"

  environment {
    variables = {
      foo = "AKIASXANV9XVIJ1YCIJ5"
    }
  }
}

```