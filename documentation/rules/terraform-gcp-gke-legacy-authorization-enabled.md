---
title: "GKE legacy authorization enabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/gke_legacy_authorization_enabled"
  id: "terraform-gcp-gke-legacy-authorization-enabled"
  display_name: "GKE legacy authorization enabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-gcp-gke-legacy-authorization-enabled{{< /copyable-code >}}

**Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster)

### Description

Legacy Authorization (ABAC) in GKE grants all authenticated users full cluster administrator privileges, violating the principle of least privilege and introducing significant security risks. When enabled, any authenticated user can perform any operation on any resource in the cluster, potentially leading to unauthorized access, data breaches, and complete cluster compromise. To secure your GKE cluster, ensure `enable_legacy_abac` is set to false as shown below:

```hcl
resource "google_container_cluster" "secure_cluster" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  enable_legacy_abac = false
}
```

## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "google_container_cluster" "negative1" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  enable_legacy_abac = false

  timeouts {
    create = "30m"
    update = "40m"
  }
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
resource "google_container_cluster" "positive1" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  enable_legacy_abac = true

  timeouts {
    create = "30m"
    update = "40m"
  }
}
```