---
title: "Team tag missing on AWS resource"
group_id: "Terraform / AWS"
meta:
  name: "aws/team_tag_not_present"
  id: "a2b3c4d5-e6f7-8901-gh23-ijkl456m7890"
  display_name: "Team tag missing on AWS resource"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `a2b3c4d5-e6f7-8901-gh23-ijkl456m7890`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging)

### Description

This check ensures that every cloud resource defined in Terraform includes a "Team" tag within the `tags` attribute, which is critical for tracking resource ownership and accountability. Without a "Team" tag (for example, `tags = { Environment = "Production" }`), it becomes difficult to determine resource owners, leading to challenges in cost allocation, incident response, and lifecycle management. If left unaddressed, the absence of this tag can result in unmanaged resources remaining active, increasing the risk of security vulnerabilities and unnecessary expenses.

## Compliant Code Examples
```terraform
# ✅ "team" tag is not a valid attribute for this resource type
resource "aws_acm_certificate_validation" "example" {
  certificate_arn         = aws_acm_certificate.example.arn
  validation_record_fqdns = [for record in aws_route53_record.example : record.fqdn]
}

```

```terraform
resource "aws_s3_bucket" "good_example" {
  bucket = "my-bucket"

  tags = {
    team = "Security" # ✅ "team" tag is present
  }
}

```

```terraform
resource "aws_s3_bucket" "good_example" {
  bucket = "my-bucket"

  tags = {
    Team = "Security" # ✅ "Team" tag is present
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_instance" "bad_example" {
  ami           = "ami-123456"
  instance_type = "t2.micro"

  tags = {
    Environment = "Production" # ❌ Missing "Team" tag
  }
}

resource "aws_s3_bucket" "bad_example" {
  bucket = "my-bucket"

  # ❌ No tags at all
}

```