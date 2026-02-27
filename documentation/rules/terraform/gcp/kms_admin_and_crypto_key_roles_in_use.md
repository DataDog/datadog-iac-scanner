---
title: "KMS admin and CryptoKey roles in use"
group_id: "Terraform / GCP"
meta:
  name: "gcp/kms_admin_and_crypto_key_roles_in_use"
  id: "92e4464a-4139-4d57-8742-b5acc0347680"
  display_name: "KMS admin and CryptoKey roles in use"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `92e4464a-4139-4d57-8742-b5acc0347680`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#policy_data)

### Description

Assigning both the `roles/cloudkms.admin` and `roles/cloudkms.cryptoKeyDecrypter` IAM roles to the same member on a Google Cloud project grants that user full administrative control over Cloud KMS keys and the ability to decrypt data. This combination of permissions allows a single user to manage (create, destroy, and modify) cryptographic keys and decrypt sensitive information, greatly increasing the risk of unauthorized data access or key misuse. To minimize risk, ensure that these roles are assigned to separate members as shown below:

```
data "google_iam_policy" "secure_example" {
  binding {
    role = "roles/cloudkms.admin"
    members = ["user:jane@example.com"]
  }
  binding {
    role = "roles/cloudkms.cryptoKeyDecrypter"
    members = ["user:jane2@example.com"]
  }
}
```

## Compliant Code Examples
```terraform
resource "google_project_iam_policy" "negative1" {
  project     = "your-project-id"
  policy_data = data.google_iam_policy.negative1.policy_data
}

data "google_iam_policy" "negative1" {
  binding {
    role = "roles/cloudkms.admin"

    members = [
      "user:jane@example.com",
    ]
  }

  binding {
    role = "roles/cloudkms.cryptoKeyDecrypter"

    members = [
      "user:jane2@example.com",
    ]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_project_iam_policy" "positive1" {
  project     = "your-project-id"
  policy_data = data.google_iam_policy.positive1.policy_data
}

data "google_iam_policy" "positive1" {
  binding {
    role = "roles/cloudkms.admin"

    members = [
      "user:jane@example.com",
    ]
  }

  binding {
    role = "roles/cloudkms.cryptoKeyDecrypter"

    members = [
      "user:jane@example.com",
    ]
  }
}

```