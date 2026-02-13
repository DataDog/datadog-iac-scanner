---
title: "Pod security policy disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/pod_security_policy_disabled"
  id: "9192e0f9-eca5-4056-9282-ae2a736a4088"
  display_name: "Pod security policy disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9192e0f9-eca5-4056-9282-ae2a736a4088`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster)

### Description

 Kubernetes clusters managed by Terraform should have the Pod Security Policy (PSP) controller enabled by setting the `pod_security_policy_config { enabled = true }` attribute in the `google_container_cluster` resource. Enabling PSP helps enforce fine-grained security controls over pod behavior, reducing the risk of privilege escalation or unauthorized access within your cluster. If left unconfigured or disabled, as in `pod_security_policy_config { enabled = false }`, workloads in the cluster may bypass key security restrictions, increasing the potential attack surface. 

A secure configuration looks like:

```
resource "google_container_cluster" "example" {
  // cluster configuration
  pod_security_policy_config {
    enabled = true
  }
}
```


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "google_container_cluster" "negative1" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  pod_security_policy_config {
        enabled = "true"
  }

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

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive2" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  pod_security_policy_config {
        enabled = false
  }

  timeouts {
    create = "30m"
    update = "40m"
  }
}

```