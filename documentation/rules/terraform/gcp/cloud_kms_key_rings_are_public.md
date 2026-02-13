---
title: "Cloud KMS key ring is anonymously or publicly accessible"
group_id: "Terraform / GCP"
meta:
  name: "gcp/cloud_kms_key_rings_are_public"
  id: "d4e5f6g7-h8i9-0jkl-mnop-qrstuvwx1234"
  display_name: "Cloud KMS key ring is anonymously or publicly accessible"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `d4e5f6g7-h8i9-0jkl-mnop-qrstuvwx1234`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_key_ring)

### Description

 Cloud KMS Key Rings store and manage cryptographic keys used for data encryption in Google Cloud. Making them publicly accessible creates severe security risks that could lead to unauthorized access to sensitive encrypted data. When IAM policies grant permissions to `allUsers` or `allAuthenticatedUsers`, it allows anyone on the internet or any authenticated Google account to access and potentially use these cryptographic keys. To properly secure key rings, ensure IAM members are specific identities (such as `user:someone@example.com`) rather than public principals (`allUsers` or `allAuthenticatedUsers`). For example, use `member = "user:someone@example.com"` instead of `member = "allUsers"` or `members = ["allAuthenticatedUsers", "user:someone@example.com"]`.


## Compliant Code Examples
```terraform
# IAM Binding compliant
resource "google_kms_key_ring_iam_binding" "good_example_binding" {
  key_ring_id = "example-key-ring"
  members     = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}

```

```terraform
# IAM Member compliant
resource "google_kms_key_ring_iam_member" "good_example_member" {
  key_ring_id = "example-key-ring"
  member      = "user:someone@example.com" # ✅ Non-public principal
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}



```
## Non-Compliant Code Examples
```terraform
# IAM Member violation
resource "google_kms_key_ring_iam_member" "bad_example_member" {
  key_ring_id = "example-key-ring"
  member      = "allUsers" # ❌ Public principal
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}

# IAM Binding violation
resource "google_kms_key_ring_iam_binding" "bad_example_binding" {
  key_ring_id = "example-key-ring"
  members     = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
  role        = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
}

```