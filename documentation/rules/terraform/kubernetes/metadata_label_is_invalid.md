---
title: "Metadata label is invalid"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/metadata_label_is_invalid"
  id: "bc3dabb6-fd50-40f8-b9ba-7429c9f1fb0e"
  display_name: "Metadata label is invalid"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `bc3dabb6-fd50-40f8-b9ba-7429c9f1fb0e`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#labels)

### Description

Checks whether any label in the resource metadata is invalid. The rule validates each label key against the regular expression `^(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?$`; when a label key does not match, the rule returns a result containing `documentId`, `resourceType`, `resourceName`, `searchKey`, `issueType`, `keyExpectedValue`, and `keyActualValue`. The `issueType` is `IncorrectValue` and `searchKey` points to the labels location (for example, `<resourceType>[<name>].metadata.labels`).

## Compliant Code Examples
```terraform
resource "kubernetes_pod" "test2" {
  metadata {
    name = "terraform-example"

    labels = {
      app = "MyApp"
    }
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

    labels = {
      app = "g**dy.l+bel"
    }
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