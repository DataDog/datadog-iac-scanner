---
title: "Dataproc clusters publicly accessible"
group_id: "Terraform / GCP"
meta:
  name: "gcp/dataproc_clusters_is_public"
  id: "e3f7a9b1-c2d3-4e5f-8901-23456789abcd"
  display_name: "Dataproc clusters publicly accessible"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `e3f7a9b1-c2d3-4e5f-8901-23456789abcd`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/dataproc_cluster_iam)

### Description

Google Cloud Dataproc clusters should not be publicly accessible as this could allow unauthorized access to sensitive data and resources. When IAM bindings or members include public principals such as `allUsers` or `allAuthenticatedUsers`, the Dataproc cluster becomes exposed to anyone on the internet or any authenticated Google account, respectively. To secure Dataproc clusters, use specific identities in IAM policies instead of public principals. For example, use `members = ["user:someone@example.com", "group:admins@example.com"]` instead of `members = ["allAuthenticatedUsers", "user:someone@example.com"]` or `member = "allUsers"`. Limiting access to specific users and groups significantly reduces the attack surface and helps maintain the principle of least privilege.

## Compliant Code Examples
```terraform
# Passing IAM Member example
resource "google_dataproc_cluster_iam_member" "good_member" {
  name   = "good-dataproc-member"
  member = "user:someone@example.com" # ✅ Non-public principal
}

```

```terraform
# Passing IAM Binding example
resource "google_dataproc_cluster_iam_binding" "good_binding" {
  name    = "good-dataproc-binding"
  members = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
}

```
## Non-Compliant Code Examples
```terraform
# Positive test case# Failing IAM Member example
resource "google_dataproc_cluster_iam_member" "bad_member" {
  name   = "bad-dataproc-member"
  member = "allUsers" # ❌ Public principal
}

# Failing IAM Binding example
resource "google_dataproc_cluster_iam_binding" "bad_binding" {
  name    = "bad-dataproc-binding"
  members = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
}

```