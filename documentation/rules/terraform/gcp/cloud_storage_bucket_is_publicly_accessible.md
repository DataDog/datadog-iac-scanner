---
title: "Cloud Storage bucket is publicly accessible"
group_id: "Terraform / GCP"
meta:
  name: "gcp/cloud_storage_bucket_is_publicly_accessible"
  id: "c010082c-76e0-4b91-91d9-6e8439e455dd"
  display_name: "Cloud Storage bucket is publicly accessible"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `c010082c-76e0-4b91-91d9-6e8439e455dd`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam)

### Description

 Granting public or anonymous access to a Google Cloud Storage bucket using Terraform, such as by setting the member to `allUsers` (anyone on the internet) or `allAuthenticatedUsers` (any authenticated Google account) in a `google_storage_bucket_iam_member` resource, exposes your data to unauthorized access. This can lead to data leaks, theft, or manipulation since anyone could potentially view, download, modify, or delete sensitive data. To prevent this, IAM bindings for storage buckets should only specify trusted user or service accounts, as shown below:

```
resource "google_storage_bucket_iam_member" "secure_example" {
  bucket = google_storage_bucket.default.name
  role   = "roles/storage.admin"
  member = "user:jane@example.com"
}
```


## Compliant Code Examples
```terraform
resource "google_storage_bucket_iam_member" "negative1" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  member = "user:jane@example.com"
}


resource "google_storage_bucket_iam_member" "negative2" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = ["user:john@example.com","user:john@example.com"]
}
```
## Non-Compliant Code Examples
```terraform
resource "google_storage_bucket_iam_member" "positive1" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  member = "allUsers"

  condition {
    title       = "expires_after_2019_12_31"
    description = "Expiring at midnight of 2019-12-31"
    expression  = "request.time < timestamp(\"2020-01-01T00:00:00Z\")"
  }
}


resource "google_storage_bucket_iam_member" "positive2" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = ["user:john@example.com","allAuthenticatedUsers"]
}
```