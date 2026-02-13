---
title: "Cloud Storage is anonymous or publicly accessible"
group_id: "Terraform / GCP"
meta:
  name: "gcp/cloud_storage_anonymous_or_publicly_accessible"
  id: "a6cd52a1-3056-4910-96a5-894de9f3f3b3"
  display_name: "Cloud Storage is anonymous or publicly accessible"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "CRITICAL"
  category: "Access Control"
---
## Metadata

**Id:** `a6cd52a1-3056-4910-96a5-894de9f3f3b3`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Critical

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket_iam#google_storage_bucket_iam_binding)

### Description

Cloud Storage Buckets configured with anonymous or public access pose significant security risks by allowing anyone on the internet to access potentially sensitive data. Including `allUsers` in IAM bindings grants access to anyone, while `allAuthenticatedUsers` grants access to any Google account holder. Both violate the principle of least privilege.

Insecure configuration example:
```
resource "google_storage_bucket_iam_binding" "insecure" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = ["user:jane@example.com", "allUsers"]
}
```

Secure configuration example:
```
resource "google_storage_bucket_iam_binding" "secure" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = ["user:jane@example.com"]
}
```

## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "google_storage_bucket_iam_binding" "negative1" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = [
    "user:jane@example.com",
  ]
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "google_storage_bucket_iam_binding" "positive1" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = []
}

resource "google_storage_bucket_iam_binding" "positive2" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = ["user:jane@example.com","allUsers"]
}

resource "google_storage_bucket_iam_binding" "positive3" {
  bucket = google_storage_bucket.default.name
  role = "roles/storage.admin"
  members = ["user:jane@example.com", "allAuthenticatedUsers"]
}
```