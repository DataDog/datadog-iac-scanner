---
title: "Service account allows access secrets"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/service_account_allows_access_secrets"
  id: "07fc3413-e572-42f7-9877-5c8fc6fccfb5"
  display_name: "Service account allows access secrets"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `07fc3413-e572-42f7-9877-5c8fc6fccfb5`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/role_binding#subject)

### Description

`kubernetes_role` and `kubernetes_cluster_role`, when bound, should not include the verbs `get`, `list`, `watch`, or `*` in rules that grant access to `secrets`.  
The rule inspects `kubernetes_role_binding` and `kubernetes_cluster_role_binding` entries that bind these roles to a `ServiceAccount` and checks the role's `rule.verbs` for any of the restricted verbs.  
Both single `rule` objects and arrays of `rule` entries are evaluated.

## Compliant Code Examples
```terraform
# Cluster Role
resource "kubernetes_cluster_role" "cluster_role_name" {
  metadata {
    name = "terraform-example-1"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "pods"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding" "example" {
  metadata {
    name = "terraform-example-2"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster_role_name"
  }
  subject {
    kind      = "User"
    name      = "admin"
    api_group = "rbac.authorization.k8s.io"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = "kube-system"
  }
  subject {
    kind      = "Group"
    name      = "system:masters"
    api_group = "rbac.authorization.k8s.io"
  }
}

# Role
resource "kubernetes_role" "role_name" {
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

resource "kubernetes_role_binding" "example" {
  metadata {
    name      = "terraform-example"
    namespace = "default"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "role_name"
  }
  subject {
    kind      = "User"
    name      = "admin"
    api_group = "rbac.authorization.k8s.io"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = "kube-system"
  }
  subject {
    kind      = "Group"
    name      = "system:masters"
    api_group = "rbac.authorization.k8s.io"
  }
}

```
## Non-Compliant Code Examples
```terraform
# Cluster Role
resource "kubernetes_cluster_role" "cluster_role_name" {
  metadata {
    name = "terraform-example-1"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "pods", "secrets"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role_binding" "example" {
  metadata {
    name = "terraform-example-2"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster_role_name"
  }
  subject {
    kind      = "User"
    name      = "admin"
    api_group = "rbac.authorization.k8s.io"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = "kube-system"
  }
  subject {
    kind      = "Group"
    name      = "system:masters"
    api_group = "rbac.authorization.k8s.io"
  }
}

# Role
resource "kubernetes_role" "role_name" {
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
   rule {
    api_groups = [""]
    resources  = ["secrets"]
    verbs      = ["*"]
  }
}

resource "kubernetes_role_binding" "example" {
  metadata {
    name      = "terraform-example"
    namespace = "default"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "role_name"
  }
  subject {
    kind      = "User"
    name      = "admin"
    api_group = "rbac.authorization.k8s.io"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = "kube-system"
  }
  subject {
    kind      = "Group"
    name      = "system:masters"
    api_group = "rbac.authorization.k8s.io"
  }
}

```