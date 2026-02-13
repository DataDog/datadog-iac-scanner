---
title: "RBAC roles with read secrets permissions"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/rbac_roles_with_read_secrets_permissions"
  id: "826abb30-3cd5-4e0b-a93b-67729b4f7e63"
  display_name: "RBAC roles with read secrets permissions"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `826abb30-3cd5-4e0b-a93b-67729b4f7e63`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/role#rule)

### Description

 Roles and ClusterRoles that grant 'get', 'watch', or 'list' RBAC permissions on Kubernetes 'secrets' are dangerous and should not include such permissions. If compromised, these roles can be used to access sensitive data such as passwords, tokens, and keys. This rule flags Role and ClusterRole resources that include rules with 'secrets' in their resources field together with any of the read verbs ('get', 'watch', 'list').


## Compliant Code Examples
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
    verbs          = ["get", "list", "watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["deployments"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_cluster_role" "example2" {
  metadata {
    name = "terraform-example2"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "pods"]
    verbs      = ["get", "list", "watch"]
  }
}

```
## Non-Compliant Code Examples
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
    resources      = ["secrets", "namespaces"]
    resource_names = ["foo"]
    verbs          = ["get", "list", "watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["deployments"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_cluster_role" "example2" {
  metadata {
    name = "terraform-example2"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "secrets"]
    verbs      = ["get", "list", "watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["deployments"]
    verbs      = ["get", "list"]
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
    resources      = ["secrets", "namespaces"]
    resource_names = ["foo"]
    verbs          = ["get", "list", "watch"]
  }

}

resource "kubernetes_cluster_role" "example4" {
  metadata {
    name = "terraform-example4"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "secrets"]
    verbs      = ["get", "list", "watch"]
  }

}

```