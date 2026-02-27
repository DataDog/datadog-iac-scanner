---
title: "Elasticsearch domain with vulnerable policy"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_domain_with_vulnerable_policy"
  id: "16c4216a-50d3-4785-bfb2-4adb5144a8ba"
  display_name: "Elasticsearch domain with vulnerable policy"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `16c4216a-50d3-4785-bfb2-4adb5144a8ba`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain_policy#access_policies)

### Description

Using a wildcard (`*`) for both `Action` and `Principal` in an `aws_elasticsearch_domain_policy`—such as `"Action": "es:*"` and `"Principal": "*"`—grants unrestricted access to the Elasticsearch domain, allowing any identity to perform any action. This broad permission model introduces a significant security vulnerability, as it may expose sensitive data and allow unauthorized users to modify or delete resources. To mitigate this risk, explicitly define trusted principals and limit actions using specific permissions in the policy document.

## Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "example2" {
  domain_name           = "tf-test"
  elasticsearch_version = "2.3"
}

resource "aws_elasticsearch_domain_policy" "main2" {
  domain_name = aws_elasticsearch_domain.example2.domain_name

  access_policies = <<POLICIES
{
    "Version": "2012-10-17",
    "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::123456789012:user/test-user"
        ]
      },
      "Action": [
        "es:ESHttpGet"
      ],
      "Resource": "arn:aws:es:us-west-1:987654321098:domain/test-domain/test-index/_search"
    }
  ]
}
POLICIES
}

```
## Non-Compliant Code Examples
```terraform
provider "aws" {
  region = "us-east-1"
}

resource "aws_elasticsearch_domain" "es-not-secure-policy" {
  domain_name = "es-not-secure-policy"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
    volume_type = "gp2"
  }
}

resource "aws_elasticsearch_domain_policy" "main" {
  domain_name = aws_elasticsearch_domain.es-not-secure-policy.domain_name

  access_policies = <<POLICIES
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal": "*",
            "Effect": "Allow"
        }
    ]
}
POLICIES
}

```