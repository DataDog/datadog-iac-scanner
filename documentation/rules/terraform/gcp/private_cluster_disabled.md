---
title: "Private cluster disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/private_cluster_disabled"
  id: "6ccb85d7-0420-4907-9380-50313f80946b"
  display_name: "Private cluster disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `6ccb85d7-0420-4907-9380-50313f80946b`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster)

### Description

Kubernetes clusters should be created with private clusters enabled by configuring the `private_cluster_config` block and setting both `enable_private_nodes` and `enable_private_endpoint` to `true`. Failing to do so allows access to the cluster’s control plane and nodes from public networks, increasing exposure to potential attacks and unauthorized access. A secure configuration in Terraform looks like:

```
resource "google_container_cluster" "secure" {
  name = "example"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
    enable_private_endpoint = true
    enable_private_nodes    = true
  }
}
```

## Compliant Code Examples
```terraform
resource "google_container_cluster" "negative1" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
        enable_private_endpoint = true
        enable_private_nodes = true
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_container_cluster" "positive1" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive2" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
        enable_private_endpoint = true
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive3" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
        enable_private_nodes = true
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive4" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {

  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive5" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
        enable_private_endpoint = false
        enable_private_nodes = true
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive6" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
        enable_private_endpoint = true
        enable_private_nodes = false
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive7" {
  name = "marcellus-wallace"
  location = "us-central1-a"
  initial_node_count = 3
  private_cluster_config {
        enable_private_endpoint = false
        enable_private_nodes = false
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

```