---
title: "Volume mount with OS directory write permissions"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/volume_mount_with_os_directory_write_permissions"
  id: "a62a99d1-8196-432f-8f80-3c100b05d62a"
  display_name: "Volume mount with OS directory write permissions"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "HIGH"
  category: "Resource Management"
---
## Metadata

**Id:** `a62a99d1-8196-432f-8f80-3c100b05d62a`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** High

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#volume_mount)

### Description

Containers can mount sensitive host folders, which may grant dangerous access to critical host configurations and binaries. This rule inspects `container` and `init_container` entries in the resource spec and evaluates each `volume_mount` (object or array) whose `mount_path` targets host-sensitive directories or `/`. The rule enforces that the `read_only` attribute is set to `true`. It reports a `MissingAttribute` if `read_only` is undefined, and an `IncorrectValue` if it is explicitly set to `false`. To remediate, add `read_only = true` when missing or replace `false` with `true` for incorrect values.

## Compliant Code Examples
```terraform
resource "kubernetes_pod" "testttt" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
      volume_mount {
        name       = "config-volume"
        mount_path = "/etc/config"
        read_only  = true
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
resource "kubernetes_pod" "test2" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
      volume_mount {
        name       = "config-volume"
        mount_path = "/bin"
        read_only = false
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

```terraform
resource "kubernetes_pod" "test3" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
      volume_mount = [
        {
          name       = "config-volume"
          mount_path = "/bin"
          read_only = false
        }

      ]

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

```terraform
resource "kubernetes_pod" "test" {
  metadata {
    name = "terraform-example"
  }

  spec {
    container {
      volume_mount {
        name       = "config-volume"
        mount_path = "/bin"
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