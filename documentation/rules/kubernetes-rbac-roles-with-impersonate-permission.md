---
title: "RBAC roles with impersonate permission"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "kubernetes/rbac_roles_with_impersonate_permission"
  id: "kubernetes-rbac-roles-with-impersonate-permission"
  display_name: "RBAC roles with impersonate permission"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-rbac-roles-with-impersonate-permission{{< /copyable-code >}}

**Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)

### Description

Roles or ClusterRoles with the `impersonate` permission allow subjects to assume the rights of other users, groups, or service accounts. If an identity with such permissions is compromised, attackers can abuse this sudo-like capability to escalate privileges and act with the impersonated principals' access. Misuse of the `impersonate` permission can enable lateral movement, persistent access, and the bypass of intended permission boundaries. For these reasons, `impersonate` is considered a high-risk permission and is commonly subject to restriction and monitoring.

## Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator-role-neg
  namespace: default
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: rbac-impersonate-binding
subjects:
- kind: ServiceAccount
  name: impersonator-sa-neg
  namespace: default
  apiGroup: ""
roleRef:
  kind: ClusterRole
  name: impersonator-role-neg
  apiGroup: ""

```
## Non-Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: rbac-impersonate-binding
subjects:
- kind: ServiceAccount
  name: impersonator-sa
  namespace: default
  apiGroup: ""
roleRef:
  kind: ClusterRole
  name: impersonator-role
  apiGroup: ""

```