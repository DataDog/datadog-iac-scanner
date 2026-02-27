---
title: "Stackdriver Logging disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/stackdriver_logging_disabled"
  id: "4c7ebcb2-eae2-461e-bc83-456ee2d4f694"
  display_name: "Stackdriver Logging disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Observability"
---
## Metadata

**Id:** `4c7ebcb2-eae2-461e-bc83-456ee2d4f694`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#logging_service)

### Description

Google Kubernetes Engine (GKE) clusters should have Stackdriver Logging enabled to ensure that logs from the cluster are collected and available for monitoring and auditing. Failing to set the `logging_service` attribute, or setting it to `"none"`, means critical cluster activity and security logs will not be captured, potentially leaving malicious or accidental changes undetected. For secure configuration, set `logging_service = "logging.googleapis.com/kubernetes"` or simply omit the attribute to use the default, as shown below:

```
resource "google_container_cluster" "secure" {
  name               = "example-cluster"
  location           = "us-central1-a"
  initial_node_count = 3
  logging_service    = "logging.googleapis.com/kubernetes"
}
```

## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
resource "google_container_cluster" "negative1" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  logging_service = "logging.googleapis.com/kubernetes"

  timeouts {
    create = "30m"
    update = "40m"
  }
}

# Logging service defaults to Stackdriver, so it's okay to be undefined
resource "google_container_cluster" "negative2" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  
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
  logging_service = "none"

  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_container_cluster" "positive2" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  logging_service = "logging.googleapis.com"

  timeouts {
    create = "30m"
    update = "40m"
  }
}
```