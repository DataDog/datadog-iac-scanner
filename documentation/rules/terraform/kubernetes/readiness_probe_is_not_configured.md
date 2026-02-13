---
title: "Readiness probe is not configured"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/readiness_probe_is_not_configured"
  id: "8657197e-3f87-4694-892b-8144701d83c1"
  display_name: "Readiness probe is not configured"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** `8657197e-3f87-4694-892b-8144701d83c1`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#readiness_probe)

### Description

 Check whether `readiness_probe` is configured for every `container` and `init_container`. The rule reports `MissingAttribute` when the `readiness_probe` key is undefined on a container object or array item. This check excludes resources of type `kubernetes_cron_job` and `kubernetes_job`.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "test2" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
      readiness_probe {
        initial_delay_seconds = 10
      }

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