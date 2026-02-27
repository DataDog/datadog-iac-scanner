---
title: "EBS volume snapshot not encrypted"
group_id: "Terraform / AWS"
meta:
  name: "aws/ebs_volume_snapshot_not_encrypted"
  id: "e6b4b943-6883-47a9-9739-7ada9568f8ca"
  display_name: "EBS volume snapshot not encrypted"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `e6b4b943-6883-47a9-9739-7ada9568f8ca`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ebs_snapshot#encrypted)

### Description

EBS volume snapshots should be encrypted to protect sensitive data at rest from unauthorized access. When an EBS snapshot is unencrypted, sensitive information is potentially exposed if accessed by malicious actors. The security impact includes potential data breaches, compliance violations, and unauthorized data access even if the original volume is no longer in use.

To ensure proper encryption, create your EBS snapshots with encryption enabled. For example:

```
resource "aws_ebs_snapshot" "secure_example" {
  volume_id = aws_ebs_volume.negative1.id
  encrypted = true
}
```

## Compliant Code Examples
```terraform
resource "aws_ebs_volume" "negative1" {
  availability_zone = "us-west-2a"
  size              = 40

  tags = {
    Name = "HelloWorld"
  }
}

resource "aws_ebs_snapshot" "negative1" {
  volume_id = aws_ebs_volume.negative1.id
  encrypted = true
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

resource "aws_ebs_snapshot" "positive2" {
  volume_id = aws_ebs_volume.positive2.id
  tags {
    Name = "Production"
  }
}

```

```terraform
resource "aws_ebs_volume" "positive1" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted = false
  tags = {
    Name = "HelloWorld"
  }
}

resource "aws_ebs_snapshot" "positive1" {
  volume_id = aws_ebs_volume.positive1.id
  encrypted         = false
}

```