---
title: "Ensure legacy networks do not exist for a project"
group_id: "Terraform / GCP"
meta:
  name: "gcp/legacy_networks_exist_for_project"
  id: "terraform-gcp-legacy-networks-exist-for-project"
  display_name: "Ensure legacy networks do not exist for a project"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `terraform-gcp-legacy-networks-exist-for-project`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://cloud.google.com/vpc/docs/legacy)

### Description

Legacy networks in Google Cloud Platform (GCP) with `auto_create_subnetworks` enabled represent a significant security risk as they automatically create subnets with predefined IP ranges in every region. This can lead to overly permissive network configurations and potentially expose internal services to unauthorized access or lateral movement within your infrastructure.

The secure configuration (as shown below) explicitly avoids enabling auto-created subnetworks, giving administrators complete control over subnet creation and IP addressing:
```hcl
resource "google_compute_network" "legacy_network_2" {
  name = "legacy-network"
}
```

Insecure configuration example with `auto_create_subnetworks` enabled:
```hcl
resource "google_compute_network" "legacy_network" {
  name                    = "legacy-network"
  auto_create_subnetworks = true
}
```

## Compliant Code Examples
```terraform
resource "google_compute_network" "modern_network" {
  name                    = "modern-network"
  auto_create_subnetworks = false
}

```
## Non-Compliant Code Examples
```terraform
resource "google_compute_network" "legacy_network" {
  name                    = "legacy-network"
  auto_create_subnetworks = true
}

```