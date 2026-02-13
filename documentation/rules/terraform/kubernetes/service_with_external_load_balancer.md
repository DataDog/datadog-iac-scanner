---
title: "Service with external load balancer"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/service_with_external_load_balancer"
  id: "2a52567c-abb8-4651-a038-52fa27c77aed"
  display_name: "Service with external load balancer"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `2a52567c-abb8-4651-a038-52fa27c77aed`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/service)

### Description

 This rule applies to `kubernetes_service` resources with `spec.type == "LoadBalancer"`, which exposes the service via an external load balancer and can make it accessible from other networks and the Internet.
`metadata.annotations` should be set to indicate an internal load balancer when the service must not be externally exposed.
Supported internal annotation keys include `networking.gke.io/load-balancer-type: Internal`, `cloud.google.com/load-balancer-type: Internal`, `service.beta.kubernetes.io/aws-load-balancer-internal: "true"`, and `service.beta.kubernetes.io/azure-load-balancer-internal: "true"`.


## Compliant Code Examples
```terraform
resource "kubernetes_service" "example2" {
  metadata {
    name = "terraform-example2"
    annotations = {
      "service.beta.kubernetes.io/azure-load-balancer-internal" = "true"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "example3" {
  metadata {
    name = "terraform-example3"
    annotations = {
      "networking.gke.io/load-balancer-type" = "Internal"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "example4" {
  metadata {
    name = "terraform-example4"
    annotations = {
      "cloud.google.com/load-balancer-type" = "Internal"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

```

```terraform
resource "kubernetes_service" "example3" {
  metadata {
    name = "terraform-example3"
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-internal" = "true"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_service" "example2" {
  metadata {
    name = "terraform-example2"
    annotations = {
      "service.beta.kubernetes.io/azure-load-balancer-internal" = "false"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "example3" {
  metadata {
    name = "terraform-example3"
    annotations = {
      "networking.gke.io/load-balancer-type" = "External"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "example4" {
  metadata {
    name = "terraform-example4"
    annotations = {
      "cloud.google.com/load-balancer-type" = "External"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

```

```terraform
resource "kubernetes_service" "example1" {
  metadata {
    name = "terraform-example1"
    annotations = {
      "service.beta.kubernetes.io/aws-load-balancer-internal" = "false"
    }
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

resource "kubernetes_service" "example2" {
  metadata {
    name = "terraform-example2"
  }
  spec {
    selector = {
      app = kubernetes_pod.example.metadata.0.labels.app
    }
    session_affinity = "ClientIP"
    port {
      port        = 8080
      target_port = 80
    }

    type = "LoadBalancer"
  }
}

```