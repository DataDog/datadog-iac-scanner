---
title: "Docker daemon socket is exposed to containers"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/docker_daemon_socket_is_exposed_to_containers"
  id: "4e203a65-c8d8-49a2-b749-b124d43c9dc1"
  display_name: "Docker daemon socket is exposed to containers"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `4e203a65-c8d8-49a2-b749-b124d43c9dc1`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#host_path)

### Description

 Detects when the Docker daemon socket is exposed to containers. Checks `kubernetes_pod` and workload kinds `kubernetes_deployment`, `kubernetes_daemonset`, `kubernetes_job`, `kubernetes_stateful_set`, `kubernetes_replication_controller`, and `kubernetes_cron_job` for volumes where `host_path.path` is `/var/run/docker.sock`. Reports an `IncorrectValue` issue and populates `keyExpectedValue` and `keyActualValue` showing that the `spec...volume[n].host_path.path` should not be `/var/run/docker.sock` and indicating the offending value.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "test2" {
  metadata {
    name = "terraform-example"
  }

  spec {

    volume = [
     {
       host_path = {
         path = "/data"
         type = "Directory"
       }
     }
     ,
     {
       host_path = {
         path = "/data"
         type = "Directory"
       }
     }
    ]

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


resource "kubernetes_deployment" "example2" {
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

        volume = [
          {
            host_path = {
              path = "/data"
              type = "Directory"
            }
          }
          ,
          {
            host_path = {
              path = "/data"
              type = "Directory"
            }
          }
        ]

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


resource "kubernetes_cron_job" "demo22" {
  metadata {
    name = "demo"
  }
  spec {
    concurrency_policy            = "Replace"
    failed_jobs_history_limit     = 5
    schedule                      = "1 0 * * *"
    starting_deadline_seconds     = 10
    successful_jobs_history_limit = 10
    job_template {
      metadata {}
      spec {
        backoff_limit              = 2
        ttl_seconds_after_finished = 10
        template {
          metadata {}
          spec {

            volume = [
              {
                host_path = {
                  path = "/data"
                  type = "Directory"
                }
              }
              ,
              {
                host_path = {
                  path = "/data"
                  type = "Directory"
                }
              }
            ]

            container {
              name    = "hello"
              image   = "busybox"
              command = ["/bin/sh", "-c", "date; echo Hello from the Kubernetes cluster"]
            }
          }
        }
      }
    }
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

    volume = [
     {
       host_path = {
         path = "/var/run/docker.sock"
         type = "Directory"
       }
     }
     ,
     {
       host_path = {
         path = "/var/run/docker.sock"
         type = "Directory"
       }
     }
    ]

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

        volume = [
          {
            host_path = {
              path = "/var/run/docker.sock"
              type = "Directory"
            }
          }
          ,
          {
            host_path = {
              path = "/var/run/docker.sock"
              type = "Directory"
            }
          }
        ]

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


resource "kubernetes_cron_job" "demo2" {
  metadata {
    name = "demo"
  }
  spec {
    concurrency_policy            = "Replace"
    failed_jobs_history_limit     = 5
    schedule                      = "1 0 * * *"
    starting_deadline_seconds     = 10
    successful_jobs_history_limit = 10
    job_template {
      metadata {}
      spec {
        backoff_limit              = 2
        ttl_seconds_after_finished = 10
        template {
          metadata {}
          spec {

            volume = [
              {
                host_path = {
                  path = "/var/run/docker.sock"
                  type = "Directory"
                }
              }
              ,
              {
                host_path = {
                  path = "/var/run/docker.sock"
                  type = "Directory"
                }
              }
            ]

            container {
              name    = "hello"
              image   = "busybox"
              command = ["/bin/sh", "-c", "date; echo Hello from the Kubernetes cluster"]
            }
          }
        }
      }
    }
  }
}

```