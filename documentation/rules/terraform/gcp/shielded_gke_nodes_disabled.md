---
title: "Shielded GKE nodes disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/shielded_gke_nodes_disabled"
  id: "terraform-gcp-shielded-gke-nodes-disabled"
  display_name: "Shielded GKE nodes disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-gcp-shielded-gke-nodes-disabled{{< /copyable-code >}}

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#enable_shielded_nodes)

### Description

GKE cluster nodes should be launched with Shielded VM enabled by setting the `enable_shielded_nodes` attribute to `true` in the `google_container_cluster` resource. Failing to enable Shielded VM features exposes cluster nodes to potential rootkit and boot-level malware attacks, as these features help ensure node integrity through secure boot and trusted platform module (TPM) protections. For secure configuration, use:

```
resource "google_container_cluster" "secure" {
  name                  = "my-gke-cluster"
  location              = "us-central1"
  enable_shielded_nodes = true
}
```

## Compliant Code Examples
```terraform
resource "google_container_cluster" "negative1" {
  name                  = "my-gke-cluster"
  location              = "us-central1"
  enable_shielded_nodes = true
}
```
## Non-Compliant Code Examples
```terraform
resource "google_container_cluster" "false" {
  name                  = "my-gke-cluster"
  location              = "us-central1"
  enable_shielded_nodes = false
}
```