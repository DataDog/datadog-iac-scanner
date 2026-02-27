---
title: "S3 bucket with all permissions"
group_id: "Terraform / AWS"
meta:
  name: "aws/s3_bucket_with_all_permissions"
  id: "a4966c4f-9141-48b8-a564-ffe9959945bc"
  display_name: "S3 bucket with all permissions"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `a4966c4f-9141-48b8-a564-ffe9959945bc`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)

### Description

When an S3 bucket policy allows all actions (`s3:*`) to all principals (`*`), it creates a severe security vulnerability by exposing your data to unauthorized access, modification, and deletion by anyone on the internet. Instead of using overly permissive policies like `s3:*`, implement the principle of least privilege by granting only specific permissions (for example, `s3:putObject`) that are required for legitimate operations. For example, replace insecure configurations like `Action`: [`s3:*`] with more restrictive ones such as `Action`: [`s3:putObject`] to ensure your S3 buckets remain protected while still enabling necessary functionality.

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

  policy = <<EOF
	{
	  "Id": "id113",
	  "Version": "2012-10-17",
	  "Statement": [
		{
		  "Action": [
			"s3:putObject"
		  ],
		  "Effect": "Allow",
		  "Resource": "arn:aws:s3:::S3B_181355/*",
		  "Principal": "*"
		}
	  ]
	}
  EOF
}

```

```terraform
resource "aws_s3_bucket" "negative1" {
  bucket = "S3B_181355"
  acl    = "private"

  policy = <<EOF
	{
	  "Id": "id113",
	  "Version": "2012-10-17",
	  "Statement": [
		{
		  "Action": [
			"s3:putObject"
		  ],
		  "Effect": "Allow",
		  "Resource": "arn:aws:s3:::S3B_181355/*",
		  "Principal": "*"
		}
	  ]
	}
  EOF
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

  policy = <<EOF
	{
	  "Id": "id113",
	  "Version": "2012-10-17",
	  "Statement": [
		{
		  "Action": [
			"s3:*"
		  ],
		  "Effect": "Allow",
		  "Resource": "arn:aws:s3:::S3B_181355/*",
		  "Principal": "*"
		}
	  ]
	}
  EOF
}

```

```terraform
resource "aws_s3_bucket" "positive1" {
  bucket = "S3B_181355"
  acl    = "private"

  policy = <<EOF
	{
	  "Id": "id113",
	  "Version": "2012-10-17",
	  "Statement": [
		{
		  "Action": [
			"s3:*"
		  ],
		  "Effect": "Allow",
		  "Resource": "arn:aws:s3:::S3B_181355/*",
		  "Principal": "*"
		}
	  ]
	}
  EOF
}

```