---
title: "RBAC roles with port-forwarding permission"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/rbac_roles_with_portforwarding_permissions"
  id: "38fa11ef-dbcc-4da8-9680-7e1fd855b6fb"
  display_name: "RBAC roles with port-forwarding permission"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `38fa11ef-dbcc-4da8-9680-7e1fd855b6fb`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Description

Roles or ClusterRoles that grant permissions to port-forward into pods can open socket-level communication channels to containers. If compromised, attackers may abuse this capability to establish direct connections that bypass network security controls. This can enable data exfiltration, remote command execution, or persistent access to containerized workloads. Limiting port-forward permissions to trusted principals and enforcing least-privilege reduces this risk.

## Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: my-namespace
  name: allow-port-forward-neg
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-port-forward-neg
  namespace: my-namespace
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: allow-port-forward-neg
  apiGroup: ""
```
## Non-Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: my-namespace
  name: allow-port-forward
rules:
- apiGroups: [""]
  resources: ["pods", "pods/portforward"]
  verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-port-forward
  namespace: my-namespace
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: allow-port-forward
  apiGroup: ""
```