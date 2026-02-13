---
title: "Secrets as environment variables"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/secrets_as_environment_variables"
  id: "6d8f1a10-b6cd-48f0-b960-f7c535d5cdb8"
  display_name: "Secrets as environment variables"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Secret Management"
---
## Metadata

**Id:** `6d8f1a10-b6cd-48f0-b960-f7c535d5cdb8`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#secret_key_ref)

### Description

 `Containers` should not include secrets as environment variables.
The rule detects any use of `env.value_from.secret_key_ref` or `env_from.secret_ref` in `container` and `init_container` entries and flags them as `IncorrectValue`.
It checks both array and object forms of `env` and `env_from` and reports the resource path where the secret reference is set.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "test55" {
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

        value_from =  {
            secret_key_ref = "hjjhjh"
        }
      }

      env_from {
        secret_ref = "wwww"
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