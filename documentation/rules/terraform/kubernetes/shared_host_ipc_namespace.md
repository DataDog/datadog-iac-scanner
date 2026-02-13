---
title: "Shared host IPC namespace"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/shared_host_ipc_namespace"
  id: "e94d3121-c2d1-4e34-a295-139bfeb73ea3"
  display_name: "Shared host IPC namespace"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `e94d3121-c2d1-4e34-a295-139bfeb73ea3`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#host_ipc)

### Description

 Containers must not share the host IPC namespace.

This rule detects resources where the `host_ipc` attribute is set to `true`; the attribute should be undefined or `false` to prevent sharing the host IPC namespace.

The rule's result includes `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, `keyActualValue`, `searchLine`, `remediation`, and `remediationType` to help locate and remediate the issue; remediation replaces `true` with `false`.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "negative1" {
  metadata {
    name = "terraform-example"
  }

  spec {

    host_ipc = false

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
resource "kubernetes_pod" "positive1" {
  metadata {
    name = "terraform-example"
  }

  spec {

    host_ipc = true

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