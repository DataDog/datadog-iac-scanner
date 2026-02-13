---
title: "Google Compute SSL policy weak cipher in use"
group_id: "Terraform / GCP"
meta:
  name: "gcp/google_compute_ssl_policy_weak_cipher_in_use"
  id: "14a457f0-473d-4d1d-9e37-6d99b355b336"
  display_name: "Google Compute SSL policy weak cipher in use"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `14a457f0-473d-4d1d-9e37-6d99b355b336`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_ssl_policy)

### Description

 This check determines whether Google Compute SSL policies enforce strong TLS versions by verifying that the `min_tls_version` attribute is set to `"TLS_1_2"`. Allowing lower TLS versions, such as `"TLS_1_1"`, exposes services to vulnerabilities associated with outdated cryptographic algorithms and weak cipher suites, increasing the risk of data breaches and interception. For example, the following secure configuration ensures strong encryption by setting `min_tls_version` to `"TLS_1_2"`:

```
resource "google_compute_ssl_policy" "example" {
  name            = "custom-ssl-policy"
  min_tls_version = "TLS_1_2"
  profile         = "CUSTOM"
  custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
}
```


## Compliant Code Examples
```terraform
resource "google_compute_ssl_policy" "negative1" {
  name            = "custom-ssl-policy"
  min_tls_version = "TLS_1_2"
  profile         = "CUSTOM"
  custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
}
```
## Non-Compliant Code Examples
```terraform
resource "google_compute_ssl_policy" "positive1" {
  name            = "custom-ssl-policy"
  min_tls_version = "TLS_1_1"
  profile         = "CUSTOM"
  custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
}

resource "google_compute_ssl_policy" "positive2" {
  name            = "custom-ssl-policy"
  profile         = "CUSTOM"
  custom_features = ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
}
```