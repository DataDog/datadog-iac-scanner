---
title: "GKE control plane is public"
group_id: "Terraform / GCP"
meta:
  name: "gcp/gke_control_plane_is_public"
  id: "e2f9b5c7-8d3a-4a5f-93b0-78aeb39d7e09"
  display_name: "GKE control plane is public"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `e2f9b5c7-8d3a-4a5f-93b0-78aeb39d7e09`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#master_authorized_networks_config)

### Description

 Google Kubernetes Engine (GKE) control plane is the management layer that controls the Kubernetes cluster. When the control plane is publicly accessible, it increases the attack surface and risk of unauthorized access to your cluster's management functionality. Exposing the control plane to the public internet (using `0.0.0.0/0` CIDR block) enables potential attackers to attempt brute force attacks or exploit vulnerabilities in the API server.

To secure your GKE cluster, restrict access to the control plane by specifying known private IP ranges in the `master_authorized_networks_config` block. For example, instead of using a public CIDR block like `cidr_block = "0.0.0.0/0"`, use a private network range such as `cidr_block = "10.0.0.0/8"` to limit access to your internal networks only.


## Compliant Code Examples
```terraform
resource "google_container_cluster" "good_example" {
  name     = "good-cluster"
  location = "us-central1"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "10.0.0.0/8" # ✅ Private network only
    }
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_container_cluster" "bad_example" {
  name     = "bad-cluster"
  location = "us-central1"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "0.0.0.0/0" # ❌ Public access
    }
  }
}

```