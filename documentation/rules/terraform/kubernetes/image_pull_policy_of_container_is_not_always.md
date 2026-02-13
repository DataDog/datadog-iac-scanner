---
title: "Image pull policy of the container is not set to always"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/image_pull_policy_of_container_is_not_always"
  id: "aa737abf-6b1d-4aba-95aa-5c160bd7f96e"
  display_name: "Image pull policy of the container is not set to always"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `aa737abf-6b1d-4aba-95aa-5c160bd7f96e`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#image_pull_policy)

### Description

 The container's `image_pull_policy` must be defined and set to `Always`.
The container image must not use the `:latest` tag.
This rule checks container paths in `kubernetes_pod` (`spec.container`) and `kubernetes_deployment` (`spec.template.spec.container`) resources.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "busybox" {
  metadata {
    name = "busybox-tf"
  }

  spec {
    container {
      image   = "busybox"
      command = ["sleep", "3600"]
      name    = "busybox"

      image_pull_policy = "Always"
    }

    restart_policy = "Always"
  }
}

```
## Non-Compliant Code Examples
```terraform

resource "kubernetes_deployment" "example" {
  metadata {
    name = "terraform-example"
    labels = {
      test = "MyExampleApp"
    }
  }

  spec {
    replicas = 3

    selector {
      match_labels = {
        test = "MyExampleApp"
      }
    }

    template {
      metadata {
        labels = {
          test = "MyExampleApp"
        }
      }

      spec {
        container {
          image             = "nginx:1.7.8"
          name              = "example"
          image_pull_policy = "IfNotPresent"

          resources {
            limits = {
              cpu    = "0.5"
              memory = "512Mi"
            }
            requests = {
              cpu    = "250m"
              memory = "50Mi"
            }
          }
        }
      }
    }
  }
}

```

```terraform
resource "kubernetes_pod" "busybox" {
  metadata {
    name = "busybox-tf"
  }

  spec {
    container {
      image   = "busybox"
      command = ["sleep", "3600"]
      name    = "busybox"

      image_pull_policy = "IfNotPresent"
    }

    restart_policy = "Always"
  }
}

```