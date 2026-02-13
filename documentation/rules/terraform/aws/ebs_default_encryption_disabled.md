---
title: "EBS default encryption disabled"
group_id: "Terraform / AWS"
meta:
  name: "aws/ebs_default_encryption_disabled"
  id: "3d3f6270-546b-443c-adb4-bb6fb2187ca6"
  display_name: "EBS default encryption disabled"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `3d3f6270-546b-443c-adb4-bb6fb2187ca6`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_encryption_by_default)

### Description

AWS Elastic Block Store (EBS) volumes should have encryption enabled by default to protect sensitive data at rest. When EBS encryption is disabled, data stored on these volumes remains in plaintext, potentially exposing confidential information if the physical storage is compromised or if the volume is improperly decommissioned. To enable default encryption, ensure that the `enabled` attribute in the `aws_ebs_encryption_by_default` resource is set to `true` or omitted (as it defaults to `true`). A secure configuration looks like the following: 
```
resource "aws_ebs_encryption_by_default" "example" {
  enabled = true
}
```

## Compliant Code Examples
```terraform
resource "aws_ebs_encryption_by_default" "negative1" {
  enabled = true
}

resource "aws_ebs_encryption_by_default" "negative2" {
  
}
```
## Non-Compliant Code Examples
```terraform
resource "aws_ebs_encryption_by_default" "positive1" {
  enabled = false
}
```