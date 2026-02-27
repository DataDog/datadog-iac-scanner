---
title: "High Google KMS crypto key rotation period"
group_id: "Terraform / GCP"
meta:
  name: "gcp/high_google_kms_crypto_key_rotation_period"
  id: "d8c57c4e-bf6f-4e32-a2bf-8643532de77b"
  display_name: "High Google KMS crypto key rotation period"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `d8c57c4e-bf6f-4e32-a2bf-8643532de77b`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_crypto_key)

### Description

It is important to configure Key Management Service (KMS) encryption keys with a `rotation_period` of 90 days or less to limit the blast radius if a key is ever compromised. Failure to set a short rotation period, or omitting the `rotation_period` attribute entirely, increases risk by allowing the same encryption key to remain in use for extended periods, making it a more valuable and longer-lived target if leaked or compromised. Properly securing this setting in Terraform involves specifying the `rotation_period` attribute within the `google_kms_crypto_key` resource, for example:

```
resource "google_kms_crypto_key" "secure_example" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "7776000s" // 90 days
  lifecycle {
    prevent_destroy = true
  }
}
```

## Compliant Code Examples
```terraform
resource "google_kms_crypto_key" "negative1" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "100000s"
  lifecycle {
    prevent_destroy = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_kms_crypto_key" "positive1" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  rotation_period = "77760009s"
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "positive2" {
  name            = "crypto-key-example"
  key_ring        = google_kms_key_ring.keyring.id
  lifecycle {
    prevent_destroy = true
  }
}

```