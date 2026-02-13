---
title: "RBAC roles with exec permission"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/rbac_roles_with_exec_permission"
  id: "c589f42c-7924-4871-aee2-1cede9bc7cbc"
  display_name: "RBAC roles with exec permission"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `c589f42c-7924-4871-aee2-1cede9bc7cbc`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Description

 Roles or ClusterRoles that grant permissions to run commands in containers via `kubectl exec` can be abused by attackers to execute malicious code if a subject is compromised. To reduce this risk, the `pods/exec` verb should not be used in production environments. Such permissions increase the attack surface and violate the principle of least privilege. When exec access is required, it should be tightly scoped to specific subjects and namespaces and regularly audited.


## Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: my-namespace
  name: allow-exec-neg
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-exec-neg
  namespace: my-namespace
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: allow-exec-neg
  apiGroup: ""
```
## Non-Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: my-namespace
  name: allow-exec
rules:
- apiGroups: [""]
  resources: ["pods", "pods/exec"]
  verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-exec
  namespace: my-namespace
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: allow-exec
  apiGroup: ""
```