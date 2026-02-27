---
title: "GKE using default service account"
group_id: "Terraform / GCP"
meta:
  name: "gcp/gke_using_default_service_account"
  id: "1c8eef02-17b1-4a3e-b01d-dcc3292d2c38"
  display_name: "GKE using default service account"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `1c8eef02-17b1-4a3e-b01d-dcc3292d2c38`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#node_config)

### Description

Kubernetes Engine Clusters should not be configured to use the default service account. Using the default service account (`node_config.service_account` not set) can grant workloads excessive permissions, increasing the risk of privilege escalation and unauthorized access to other Google Cloud resources if a node is compromised. To mitigate this, assign a dedicated and minimally privileged service account as shown below:

```
resource "google_container_cluster" "example" {
  // ...
  node_config {
    service_account = google_service_account.custom_sa.email
    // ...
  }
}
```

## Compliant Code Examples
```terraform
resource "google_container_cluster" "negative1" {
  name     = "my-gke-cluster"
  location = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1

  node_config {
    service_account = google_service_account.myserviceaccount.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    labels = {
      foo = "bar"
    }
    tags = ["foo", "bar"]
  }
  timeouts {
    create = "30m"
    update = "40m"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_container_cluster" "positive2" {
  name     = "my-gke-cluster"
  location = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1

  node_config {
    service_account = google_service_account.default.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    labels = {
      foo = "bar"
    }
    tags = ["foo", "bar"]
  }
  timeouts {
    create = "30m"
    update = "40m"
  }
}

```

```terraform
resource "google_container_cluster" "positive1" {
  name     = "my-gke-cluster"
  location = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1

  node_config {
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
    labels = {
      foo = "bar"
    }
    tags = ["foo", "bar"]
  }
  timeouts {
    create = "30m"
    update = "40m"
  }
}

```