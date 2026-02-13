---
title: "Google Compute subnetwork logging disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/google_compute_subnetwork_logging_disabled"
  id: "40430747-442d-450a-a34f-dc57149f4609"
  display_name: "Google Compute subnetwork logging disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `40430747-442d-450a-a34f-dc57149f4609`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork)

### Description

 This check verifies whether VPC flow logs are enabled for a `google_compute_subnetwork` resource by ensuring a `log_config` block is included in the Terraform configuration. Without flow logs enabled, as shown below, critical network traffic information is not captured, making it difficult to monitor, detect, or investigate suspicious activity within the network.  

```
resource "google_compute_subnetwork" "example" {
  // ...subnetwork configuration...

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
```

Failure to enable logging can lead to security gaps, reducing visibility into potential breaches and making compliance with auditing requirements more challenging.


## Compliant Code Examples
```terraform
resource "google_compute_subnetwork" "negative1" {
  name          = "log-test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.custom-test.id

  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "google_compute_subnetwork" "positive1" {
  name          = "log-test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.custom-test.id
}
```