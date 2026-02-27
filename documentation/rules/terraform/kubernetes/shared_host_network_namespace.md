---
title: "Shared host network namespace"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/shared_host_network_namespace"
  id: "ac1564a3-c324-4747-9fa1-9dfc234dace0"
  display_name: "Shared host network namespace"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `ac1564a3-c324-4747-9fa1-9dfc234dace0`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#host_network)

### Description

Containers should not share the host network namespace. The `host_network` field in the container spec must be undefined or set to false. Sharing the host network exposes the host's network stack to the container and can lead to privilege escalation, port conflicts, and unintended access to host network resources.

## Compliant Code Examples
```terraform
resource "kubernetes_pod" "test2" {
  metadata {
    name = "terraform-example"
  }

  spec {
    host_network = false
    container {
      image = "nginx:1.7.9"
      name  = "example"

      env {
        name  = "environment"
        value = "test"
      }

      port {
        container_port = 8080
      }

      liveness_probe {
        http_get {
          path = "/nginx_status"
          port = 80

          http_header {
            name  = "X-Custom-Header"
            value = "Awesome"
          }
        }

        initial_delay_seconds = 3
        period_seconds        = 3
      }
    }

    dns_config {
      nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
      searches    = ["example.com"]

      option {
        name  = "ndots"
        value = 1
      }

      option {
        name = "use-vc"
      }
    }

    dns_policy = "None"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_pod" "test" {
  metadata {
    name = "terraform-example"
  }

  spec {
    host_network = true
    container {
      image = "nginx:1.7.9"
      name  = "example"

      env {
        name  = "environment"
        value = "test"
      }

      port {
        container_port = 8080
      }

      liveness_probe {
        http_get {
          path = "/nginx_status"
          port = 80

          http_header {
            name  = "X-Custom-Header"
            value = "Awesome"
          }
        }

        initial_delay_seconds = 3
        period_seconds        = 3
      }
    }

    dns_config {
      nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
      searches    = ["example.com"]

      option {
        name  = "ndots"
        value = 1
      }

      option {
        name = "use-vc"
      }
    }

    dns_policy = "None"
  }
}

```