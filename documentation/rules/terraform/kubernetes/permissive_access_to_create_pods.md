---
title: "Permissive access to create pods"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/permissive_access_to_create_pods"
  id: "522d4a64-4dc9-44bd-9240-7d8a0d5cb5ba"
  display_name: "Permissive access to create pods"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `522d4a64-4dc9-44bd-9240-7d8a0d5cb5ba`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/role#rule)

### Description

 The permission to create `pods` in a cluster should be restricted because it allows privilege escalation. This rule inspects `kubernetes_role` and `kubernetes_cluster_role` resources and reports when a rule's `verbs` contains `create` while its `resources` contains `pods` or a wildcard value. It also flags cases where `verbs` or `resources` contain a wildcard (for example, `*`) in combination with `pods`, since those broaden access and can enable pod creation. Restricting these permissions reduces the risk of workloads obtaining elevated privileges.


## Compliant Code Examples
```terraform
resource "kubernetes_cluster_role" "example" {
  metadata {
    name = "terraform-example"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "pods"]
    verbs      = ["get", "list", "watch"]
  }
}

```

```terraform
resource "kubernetes_role" "example" {
  metadata {
    name = "terraform-example"
    labels = {
      test = "MyRole"
    }
  }

  rule {
    api_groups     = [""]
    resources      = ["pods"]
    resource_names = ["foo"]
    verbs          = ["get", "list", "watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["deployments"]
    verbs      = ["get", "list"]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_cluster_role" "example1" {
  metadata {
    name = "terraform-example1"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "pods"]
    verbs      = ["create", "list", "watch"]
  }
}

resource "kubernetes_cluster_role" "example2" {
  metadata {
    name = "terraform-example2"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "*"]
    verbs      = ["create", "list", "watch"]
  }
}

resource "kubernetes_cluster_role" "example3" {
  metadata {
    name = "terraform-example3"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "*"]
    verbs      = ["*", "list", "watch"]
  }
}

resource "kubernetes_cluster_role" "example4" {
  metadata {
    name = "terraform-example4"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "pods"]
    verbs      = ["*", "list", "watch"]
  }
}

```

```terraform
resource "kubernetes_role" "example1" {
  metadata {
    name = "terraform-example1"
    labels = {
      test = "MyRole"
    }
  }

  rule {
    api_groups     = [""]
    resources      = ["pods"]
    resource_names = ["foo"]
    verbs          = ["create", "list", "watch"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_role" "example2" {
  metadata {
    name = "terraform-example2"
    labels = {
      test = "MyRole"
    }
  }

  rule {
    api_groups     = [""]
    resources      = ["*"]
    resource_names = ["foo"]
    verbs          = ["create", "list", "watch"]
  }
}

resource "kubernetes_role" "example3" {
  metadata {
    name = "terraform-example3"
    labels = {
      test = "MyRole"
    }
  }

  rule {
    api_groups     = [""]
    resources      = ["pods"]
    resource_names = ["foo"]
    verbs          = ["*", "list", "watch"]
  }
}

resource "kubernetes_role" "example4" {
  metadata {
    name = "terraform-example4"
    labels = {
      test = "MyRole"
    }
  }

  rule {
    api_groups     = [""]
    resources      = ["*"]
    resource_names = ["foo"]
    verbs          = ["*", "list", "watch"]
  }
}

```