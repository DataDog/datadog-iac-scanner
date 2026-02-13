---
title: "Elasticsearch without slow logs"
group_id: "Terraform / AWS"
meta:
  name: "aws/elasticsearch_without_slow_logs"
  id: "e979fcbc-df6c-422d-9458-c33d65e71c45"
  display_name: "Elasticsearch without slow logs"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `e979fcbc-df6c-422d-9458-c33d65e71c45`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_publishing_options)

### Description

 This check ensures that Amazon Elasticsearch domains have slow logs enabled by verifying the `log_publishing_options` block includes `log_type = "INDEX_SLOW_LOGS"` and `enabled = true`. Without slow logs, it is difficult to detect and diagnose performance issues such as slow queries or inefficient indexing, which could lead to system outages or degraded search performance. Enabling slow logs provides critical visibility into the behavior of the Elasticsearch cluster, allowing for faster investigation and mitigation of operational problems.

```
resource "aws_elasticsearch_domain" "example" {
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true
  }
}
```


## Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "negative1" {

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true //for default its true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_elasticsearch_domain" "positive1" {
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "ES_APPLICATION_LOGS"
    enabled                  = true
  }
}

```