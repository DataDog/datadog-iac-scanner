---
title: "Elasticsearch without IAM authentication"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_without_iam_authentication"
  id: "e7530c3c-b7cf-4149-8db9-d037a0b5268e"
  display_name: "Elasticsearch without IAM authentication"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `e7530c3c-b7cf-4149-8db9-d037a0b5268e`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain)

### Description

AWS Elasticsearch domains should enforce IAM authentication to restrict access to authorized users only. Without proper IAM policies—such as using `"Principal": "*"` in the `aws_elasticsearch_domain_policy` resource—unauthorized users could gain access to sensitive data by connecting from approved IP addresses. To mitigate this risk, the `Principal` field should be set to reference specific IAM principals, as shown below:

```
"Principal" : {
  "AWS": [
    "arn:aws:iam::123456789012:root",
    "arn:aws:iam::555555555555:root"
    ]
}
```

Failing to enforce IAM authentication can expose your Elasticsearch domain to unauthorized access and potential data breaches.

## Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "negativee" {
  domain_name           = "tf-test"
  elasticsearch_version = "2.3"
}

resource "aws_elasticsearch_domain_policy" "main8" {
  domain_name = aws_elasticsearch_domain.negativee.domain_name

  access_policies = <<POLICIES
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal" : {
              "AWS": [
                "arn:aws:iam::123456789012:root",
                "arn:aws:iam::555555555555:root"
                ]
            },
            "Effect": "Allow",
            "Condition": {
                "IpAddress": {"aws:SourceIp": "127.0.0.1/32"}
            },
            "Resource": "${aws_elasticsearch_domain.negativee.arn}/*"
        }
    ]
}
POLICIES
}

```
## Non-Compliant Code Examples
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
            "Action": "es:*",
            "Effect": "Allow",
            "Condition": {
                "IpAddress": {"aws:SourceIp": "127.0.0.1/32"}
            },
            "Resource": "${aws_elasticsearch_domain.example2.arn}/*"
        }
    ]
}
POLICIES
}

```

```terraform
resource "aws_elasticsearch_domain" "example" {
  domain_name           = "tf-test"
  elasticsearch_version = "2.3"
}

resource "aws_elasticsearch_domain_policy" "main" {
  domain_name = aws_elasticsearch_domain.example.domain_name

  access_policies = <<POLICIES
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "es:*",
            "Principal": "*",
            "Effect": "Allow",
            "Condition": {
                "IpAddress": {"aws:SourceIp": "127.0.0.1/32"}
            },
            "Resource": "${aws_elasticsearch_domain.example.arn}/*"
        }
    ]
}
POLICIES
}

```