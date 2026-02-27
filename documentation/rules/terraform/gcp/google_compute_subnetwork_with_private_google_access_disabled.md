---
title: "Google Compute subnetwork with private Google access disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/google_compute_subnetwork_with_private_google_access_disabled"
  id: "ee7b93c1-b3f8-4a3b-9588-146d481814f5"
  display_name: "Google Compute subnetwork with private Google access disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ee7b93c1-b3f8-4a3b-9588-146d481814f5`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_subnetwork#private_ip_google_access)

### Description

Enabling Private Google Access for a Google Compute Subnetwork by setting the `private_ip_google_access` attribute to `true` allows resources with only internal IP addresses to access Google APIs and services securely, without requiring external IP addresses. If this setting is not enabled, resources within the subnetwork are unable to directly reach Google services without public internet routes, increasing the risk of misconfigurations that may expose internal resources or disrupt service communications. To address this, ensure the configuration includes `private_ip_google_access = true`:

```
resource "google_compute_subnetwork" "example" {
  name                     = "secure-subnetwork"
  ip_cidr_range            = "10.2.0.0/16"
  region                   = "us-central1"
  network                  = google_compute_network.custom-test.id
  private_ip_google_access = true
}
```

## Compliant Code Examples
```terraform
resource "google_compute_subnetwork" "negative1" {
  name          = "test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.custom-test.id
  secondary_ip_range {
    range_name    = "tf-test-secondary-range-update1"
    ip_cidr_range = "192.168.10.0/24"
  }
  private_ip_google_access = true
}

resource "google_compute_network" "custom-test" {
  name                    = "test-network"
  auto_create_subnetworks = false
}

```
## Non-Compliant Code Examples
```terraform
resource "google_compute_subnetwork" "positive2" {
  name          = "test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.custom-test.id
  secondary_ip_range {
    range_name    = "tf-test-secondary-range-update1"
    ip_cidr_range = "192.168.10.0/24"
  }
  private_ip_google_access = false
}

resource "google_compute_network" "custom-test" {
  name                    = "test-network"
  auto_create_subnetworks = false
}

```

```terraform
resource "google_compute_subnetwork" "positive1" {
  name          = "test-subnetwork"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-central1"
  network       = google_compute_network.custom-test.id
  secondary_ip_range {
    range_name    = "tf-test-secondary-range-update1"
    ip_cidr_range = "192.168.10.0/24"
  }
}

resource "google_compute_network" "custom-test" {
  name                    = "test-network"
  auto_create_subnetworks = false
}

```