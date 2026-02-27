---
title: "Service account name undefined or empty"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/service_account_name_undefined_or_empty"
  id: "24b132df-5cc7-4823-8029-f898e1c50b72"
  display_name: "Service account name undefined or empty"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `24b132df-5cc7-4823-8029-f898e1c50b72`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#service_account_name)

### Description

A Kubernetes Pod must have a Service Account defined to restrict access to the Kubernetes API. The pod spec attribute `service_account_name` must be defined and not empty or null. Pods missing a valid `service_account_name` can have excessive permissions or fail to authenticate when accessing the API.

## Compliant Code Examples
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

    service_account_name = "service_name"

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
resource "kubernetes_pod" "test2" {
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

    service_account_name = null
  }

}


```

```terraform
resource "kubernetes_pod" "test3" {
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

    service_account_name = ""
  }
}

```

```terraform
resource "kubernetes_pod" "test1" {
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
  }
}

```