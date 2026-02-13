---
title: "EBS volume encryption disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/ebs_volume_encryption_disabled"
  id: "cc997676-481b-4e93-aa81-d19f8c5e9b12"
  display_name: "EBS volume encryption disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `cc997676-481b-4e93-aa81-d19f8c5e9b12`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume#encrypted)

### Description

 This check verifies that Amazon Elastic Block Store (EBS) volumes have encryption enabled. EBS volumes store data in an unencrypted format by default, which could expose sensitive information if the volume is compromised. When encryption is enabled, all data stored at rest on the volume, disk I/O, and snapshots created from the volume are encrypted, providing an additional layer of data protection. To enable encryption, set the `encrypted` parameter to `true` in your EBS volume configuration. For example: `resource "aws_ebs_volume" "secure_example" { availability_zone = "us-west-2a", size = 40, encrypted = true }`. Leaving encryption disabled can lead to data exposure risks and may violate compliance requirements for sensitive data protection.


## Compliant Code Examples
```terraform
resource "aws_ebs_volume" "negative1" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = true

  tags = {
    Name = "HelloWorld"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_ebs_volume" "positive2" {
  availability_zone = "us-west-2a"
  size              = 40

  tags = {
    Name = "HelloWorld"
  }
}

```

```terraform
resource "aws_ebs_volume" "positive1" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false

  tags = {
    Name = "HelloWorld"
  }
}

```