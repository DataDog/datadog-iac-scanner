---
title: "AMI shared with multiple accounts"
group_id: "Terraform / AWS"
meta:
  name: "aws/ami_shared_with_multiple_accounts"
  id: "ba4e0031-3e9d-4d7d-b0d6-bd8f003f8698"
  display_name: "AMI shared with multiple accounts"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `ba4e0031-3e9d-4d7d-b0d6-bd8f003f8698`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ami_launch_permission)

### Description

This check ensures that Amazon Machine Images (AMIs) are not granted launch permissions to multiple AWS accounts, which is controlled by the `aws_ami_launch_permission` resource's `account_id` attribute. Allowing more than one account to access the same AMI, as shown below, can lead to unauthorized use or distribution of potentially sensitive images:

```
resource "aws_ami_launch_permission" "positive1" {
  image_id   = "ami-1235678"
  account_id = "12345600012"
}

resource "aws_ami_launch_permission" "positive2" {
  image_id   = "ami-1235678"
  account_id = "123456789012"
}
```

If misconfigured, this may result in exposure of proprietary software or internal system images to unintended parties, increasing the risk of data leakage and compromise of your infrastructure. To mitigate this risk, only a single, trusted account should be granted access to each AMI, as shown below:

```
resource "aws_ami_launch_permission" "secure_example" {
  image_id   = "ami-1235678"
  account_id = "123456789012"
}
```

## Compliant Code Examples
```terraform
resource "aws_ami_launch_permission" "negative1" {
  image_id   = "ami-12345678"
  account_id = "123456789012"
}


resource "aws_ami_launch_permission" "example" {
  image_id   = "ami-12345680"
  account_id = "12345672"
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_ami_launch_permission" "positive1" {

  image_id   = "ami-1235678"
  account_id = "12345600012"

}


resource "aws_ami_launch_permission" "positive2" {

  image_id   = "ami-1235678"
  account_id = "123456789012"

}
```