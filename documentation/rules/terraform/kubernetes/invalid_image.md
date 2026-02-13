---
title: "Invalid image"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/invalid_image"
  id: "e76cca7c-c3f9-4fc9-884c-b2831168ebd8"
  display_name: "Invalid image"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Supply-Chain"
---
## Metadata

**Id:** `e76cca7c-c3f9-4fc9-884c-b2831168ebd8`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Supply-Chain

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#image)

### Description

 The `image` attribute must be set and must not be empty or equal to `latest`.
The rule evaluates both `container` and `init_container` entries in resource specs and supports array and object forms.
It reports `MissingAttribute` when `image` is absent and `IncorrectValue` when `image` is empty or set to `latest`.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "negative" {
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
## Non-Compliant Code Examples
```terraform
resource "kubernetes_pod" "positive1" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
      image = ""
      name  = "example"

      env = {
        name  = "environment"
        value = "test"
      }

      port = {
        container_port = 8080
      }

      liveness_probe = {
        http_get  = {
          path = "/nginx_status"
          port = 80

          http_header = {
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

resource "kubernetes_pod" "positive2" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
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


resource "kubernetes_pod" "positive3" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container = [
      {
        image = "latest"
        name  = "example"

        env = {
          name  = "environment"
          value = "test"
        }

        port = {
          container_port = 8080
        }

        liveness_probe = {
          http_get = {
            path = "/nginx_status"
            port = 80

            http_header = {
              name  = "X-Custom-Header"
              value = "Awesome"
            }
          }

          initial_delay_seconds = 3
          period_seconds        = 3
        }
      }
    ]

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