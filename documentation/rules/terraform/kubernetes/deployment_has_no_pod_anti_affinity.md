---
title: "Deployment has no podAntiAffinity"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/deployment_has_no_pod_anti_affinity"
  id: "461ed7e4-f8d5-4bc1-b3c6-64ddb4fd00a3"
  display_name: "Deployment has no podAntiAffinity"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `461ed7e4-f8d5-4bc1-b3c6-64ddb4fd00a3`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/deployment#affinity)

### Description

 Checks whether Deployment resources with `replicas > 2` include a `podAntiAffinity` policy to prevent multiple pods from being scheduled on the same node. The rule verifies that `.spec.template.spec.affinity.pod_anti_affinity` is present and that either `required_during_scheduling_ignored_during_execution` or `preferred_during_scheduling_ignored_during_execution` is configured. It also ensures the `topology_key` is set to `kubernetes.io/hostname` and that the `label_selector.match_labels` entries match labels on the Pod template.


## Compliant Code Examples
```terraform
resource "kubernetes_deployment" "example433" {
  metadata {
    name = "terraform-example"
    labels = {
      k8s-app = "prometheus"
    }
  }

  spec {
    replicas = 3

    selector {
      match_labels = {
        k8s-app = "prometheus"
      }
    }

    template {
      metadata {
        labels = {
          k8s-app = "prometheus"
        }
      }

      spec {
        affinity {
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100

              pod_affinity_term {
                label_selector {
                  match_labels {
                    k8s-app = "prometheus"
                  }
                }

                topology_key = "kubernetes.io/hostname"
              }
            }
         }
        }

        container {
          image = "nginx:1.7.8"
          name  = "example"

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
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_deployment" "example2" {
  metadata {
    name = "terraform-example"
    labels = {
      k8s-app = "prometheus"
    }
  }

  spec {
    replicas = 3

    selector {
      match_labels = {
        k8s-app = "prometheus"
      }
    }

    template {
      metadata {
        labels = {
          k8s-app = "prometheus"
        }
      }

      spec {
        affinity {
          pod_affinity {
              required_during_scheduling_ignored_during_execution {
                label_selector {
                  match_expressions {
                    key      = "security"
                    operator = "In"
                    values   = ["S1"]
                  }
                }

                topology_key = "failure-domain.beta.kubernetes.io/zone"
              }
          }
        }

        container {
          image = "nginx:1.7.8"
          name  = "example"

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
  }
}

```

```terraform
resource "kubernetes_deployment" "example3" {
  metadata {
    name = "terraform-example"
    labels = {
      k8s-app = "prometheus"
    }
  }

  spec {
    replicas = 3

    selector {
      match_labels = {
        k8s-app = "prometheus"
      }
    }

    template {
      metadata {
        labels = {
          k8s-app = "prometheus"
        }
      }

      spec {
        affinity {
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100

              pod_affinity_term {
                label_selector {
                  match_expressions {
                    key      = "security"
                    operator = "In"
                    values   = ["S2"]
                  }
                }

                topology_key = "failure-domain.beta.kubernetes.io/zone"
              }
            }
         }
        }

        container {
          image = "nginx:1.7.8"
          name  = "example"

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
  }
}

```

```terraform
resource "kubernetes_deployment" "example4" {
  metadata {
    name = "terraform-example"
    labels = {
      k8s-app = "prometheus"
    }
  }

  spec {
    replicas = 3

    selector {
      match_labels = {
        k8s-app = "prometheus"
      }
    }

    template {
      metadata {
        labels = {
          k8s-app = "prometheus"
        }
      }

      spec {
        affinity {
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 100

              pod_affinity_term {
                label_selector {
                  match_labels {
                    k8s-app = "prometheus2"
                  }
                }

                topology_key = "kubernetes.io/hostname"
              }
            }
         }
        }

        container {
          image = "nginx:1.7.8"
          name  = "example"

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
  }
}

```