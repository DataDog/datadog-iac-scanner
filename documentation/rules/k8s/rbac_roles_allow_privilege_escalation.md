---
title: "RBAC roles allow privilege escalation"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/rbac_roles_allow_privilege_escalation"
  id: "8320826e-7a9c-4b0b-9535-578333193432"
  display_name: "RBAC roles allow privilege escalation"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `8320826e-7a9c-4b0b-9535-578333193432`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-binding-creation-or-update)

### Description

 Roles or ClusterRoles that include `bind` or `escalate` permissions allow subjects to create new bindings with other roles. These permissions enable privilege escalation, because users with them can bind to roles that may exceed their own privileges and gain unauthorized elevated access. This rule flags Role and ClusterRole objects whose rules include `bind` or `escalate` for the `roles` or `clusterroles` resources.


## Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: not-rbac-binder
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["create"]

```
## Non-Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: rbac-binder
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles"]
  verbs: ["bind"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings"]
  verbs: ["create"]

```