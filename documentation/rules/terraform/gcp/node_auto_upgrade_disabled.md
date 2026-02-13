---
title: "Node auto upgrade disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/node_auto_upgrade_disabled"
  id: "b139213e-7d24-49c2-8025-c18faa21ecaa"
  display_name: "Node auto upgrade disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `b139213e-7d24-49c2-8025-c18faa21ecaa`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_node_pool#auto_upgrade)

### Description

 Kubernetes nodes should have automatic upgrades enabled to ensure that critical security patches, bug fixes, and feature updates are applied without manual intervention. In Terraform, this is configured by setting the `auto_upgrade` attribute to `true` within the `management` block:

```
management {
  auto_upgrade = true
}
```

If `auto_upgrade` is not enabled, as in the following example, nodes may remain outdated and vulnerable to known security flaws:

```
management {
  auto_upgrade = false
}
```

Leaving auto upgrade disabled can expose your cluster to exploits and instability due to unpatched vulnerabilities in the underlying infrastructure.


## Compliant Code Examples
```terraform
resource "google_container_node_pool" "negative1" {
  name       = "my-node-pool"
  location   = "us-central1-a"
  cluster    = google_container_cluster.primary.name
  node_count = 3

  management {
    auto_upgrade = true
  }

  timeouts {
    create = "30m"
    update = "20m"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "google_container_node_pool" "positive1" {
  name       = "my-node-pool"
  location   = "us-central1-a"
  cluster    = google_container_cluster.primary.name
  node_count = 3

  timeouts {
    create = "30m"
    update = "20m"
  }
}

resource "google_container_node_pool" "positive2" {
  name       = "my-node-pool"
  location   = "us-central1-a"
  cluster    = google_container_cluster.primary.name
  node_count = 3

  management {
    auto_repair = true
  }

  timeouts {
    create = "30m"
    update = "20m"
  }
}

resource "google_container_node_pool" "positive3" {
  name       = "my-node-pool"
  location   = "us-central1-a"
  cluster    = google_container_cluster.primary.name
  node_count = 3

  management {
    auto_upgrade = false
  }

  timeouts {
    create = "30m"
    update = "20m"
  }
}

```