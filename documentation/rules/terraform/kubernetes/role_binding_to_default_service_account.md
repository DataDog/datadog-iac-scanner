---
title: "Role binding to default service account"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/role_binding_to_default_service_account"
  id: "terraform-common-role-binding-to-default-service-account"
  display_name: "Role binding to default service account"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `terraform-common-role-binding-to-default-service-account`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/role_binding#subject)

### Description

No `RoleBinding` or `ClusterRoleBinding` should bind to the default `ServiceAccount`.
The rule detects `resource.kubernetes_role_binding` entries where `subject[].kind` is `ServiceAccount` and `subject[].name` is `default`.
Bindings to the default `ServiceAccount` can grant unintended privileges; prefer distinct service accounts to limit access.

## Compliant Code Examples
```terraform
resource "kubernetes_role_binding" "example2" {
  metadata {
    name      = "terraform-example"
    namespace = "default"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "admin"
  }
  subject {
    kind      = "User"
    name      = "admin"
    api_group = "rbac.authorization.k8s.io"
  }
  subject {
    kind      = "ServiceAccount"
    name      = "serviceExample"
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
resource "kubernetes_role_binding" "example" {
  metadata {
    name      = "terraform-example"
    namespace = "default"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "admin"
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