---
title: "BigQuery dataset is public"
group_id: "Terraform / GCP"
meta:
  name: "gcp/bigquery_dataset_is_public"
  id: "e576ce44-dd03-4022-a8c0-3906acca2ab4"
  display_name: "BigQuery dataset is public"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `e576ce44-dd03-4022-a8c0-3906acca2ab4`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/providers/google/r/bigquery_dataset.html)

### Description

 This check identifies BigQuery datasets configured to allow public or anonymous access, which can expose sensitive data to unauthorized users and increase the risk of data breaches. The vulnerability occurs when access controls use the special groups `allAuthenticatedUsers` or `allUsers`, effectively making data available to anyone with a Google account or the general public. To secure your BigQuery dataset, restrict access to specific users, groups, or domains instead of using public access groups, as shown in the example below:

```terraform
access {
  role          = "OWNER"
  user_by_email = google_service_account.bqowner.email
}

access {
  role   = "READER"
  domain = "hashicorp.com"
}
```


## Compliant Code Examples
```terraform
# negative sample
resource "google_bigquery_dataset" "negative1" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    env = "default"
  }

  access {
    role          = "OWNER"
    user_by_email = google_service_account.bqowner.email
  }

  access {
    role   = "READER"
    domain = "hashicorp.com"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_bigquery_dataset" "positive1" {
  dataset_id                  = "example_dataset"
  friendly_name               = "test"
  description                 = "This is a test description"
  location                    = "EU"
  default_table_expiration_ms = 3600000

  labels = {
    env = "default"
  }

  access {
    role          = "OWNER"
    special_group = "allAuthenticatedUsers"
  }
}
```