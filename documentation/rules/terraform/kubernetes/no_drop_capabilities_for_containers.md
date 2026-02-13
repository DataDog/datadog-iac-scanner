---
title: "No drop capabilities for containers"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/no_drop_capabilities_for_containers"
  id: "21cef75f-289f-470e-8038-c7cee0664164"
  display_name: "No drop capabilities for containers"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `21cef75f-289f-470e-8038-c7cee0664164`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#drop)

### Description

 Checks whether the Kubernetes 'capabilities.drop' setting is present to ensure container security context. The rule verifies that each container and init_container defines 'security_context', that 'capabilities' exists, and that 'capabilities.drop' is set. Missing or undefined attributes are reported as missing or incorrect values.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "negative4" {
  metadata {
    name = "terraform-example"
  }

  spec {

    container =  [
      {
        image = "nginx:1.7.9"
        name  = "example"

        security_context = {
          capabilities = {
            drop = ["ALL"]
          }
        }

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
      },

      {
        image = "nginx:1.7.9"
        name  = "example2"

        security_context = {
          capabilities = {
            drop = ["ALL"]
          }
        }

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
## Non-Compliant Code Examples
```terraform

resource "kubernetes_pod" "test2" {
  metadata {
    name = "terraform-example"
  }

  spec {

    container =  [
      {
        image = "nginx:1.7.9"
        name  = "example"

        security_context = {
          allow_privilege_escalation = false
        }

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
      },

      {
        image = "nginx:1.7.9"
        name  = "example2"

        security_context = {
          capabilities = {
            drop = ["ALL"]
          }
        }

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

```terraform

resource "kubernetes_pod" "test3" {
  metadata {
    name = "terraform-example"
  }

  spec {

    container =  [
      {
        image = "nginx:1.7.9"
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
      },

      {
        image = "nginx:1.7.9"
        name  = "example2"

        security_context = {
          capabilities = {
            drop = ["ALL"]
          }
        }

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

```terraform
resource "kubernetes_pod" "test1" {
  metadata {
    name = "terraform-example"
  }

  spec {

    container =  [
      {
        image = "nginx:1.7.9"
        name  = "example"

        security_context = {
          capabilities = {
             add = ["NET_BIND_SERVICE"]
          }
        }

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
      },

      {
        image = "nginx:1.7.9"
        name  = "example2"

        security_context = {
          capabilities = {
            drop = ["ALL"]
          }
        }

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