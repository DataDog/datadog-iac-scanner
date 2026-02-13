---
title: "Cluster admin rolebinding with superuser permissions"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/cluster_admin_role_binding_with_super_user_permissions"
  id: "17172bc2-56fb-4f17-916f-a014147706cd"
  display_name: "Cluster admin rolebinding with superuser permissions"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `17172bc2-56fb-4f17-916f-a014147706cd`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/cluster_role_binding#name)

### Description

 Ensure the `cluster-admin` role is only used where required for RBAC.
The `cluster-admin` role grants superuser permissions across the entire cluster and should be limited to essential administrative accounts. This rule flags `kubernetes_cluster_role_binding` resources that bind to `cluster-admin`. Prefer using least-privilege roles or scoped `RoleBinding` assignments instead.


## Compliant Code Examples
```terraform
resource "kubernetes_cluster_role_binding" "example1" {
  metadata {
    name = "terraform-example1"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster"
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
resource "kubernetes_cluster_role_binding" "example2" {
  metadata {
    name = "terraform-example2"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "cluster-admin"
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