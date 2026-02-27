---
title: "RBAC roles with read secrets permissions"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/rbac_roles_with_read_secrets_permissions"
  id: "b7bca5c4-1dab-4c2c-8cbe-3050b9d59b14"
  display_name: "RBAC roles with read secrets permissions"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `b7bca5c4-1dab-4c2c-8cbe-3050b9d59b14`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Description

Roles and ClusterRoles with `get`, `watch`, or `list` permissions on Kubernetes Secrets are dangerous and should be avoided.
These permissions allow read access to Secrets objects across the scope of the Role or ClusterRole. In case of compromise, attackers could abuse these roles to access sensitive data such as passwords, tokens, and keys, increasing the blast radius.
This policy flags Role and ClusterRole rules that grant the `get`, `watch`, or `list` verbs on the `secrets` resource.

## Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: role-pod-and-logs-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/logs"]
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-role-pod-and-pod-logs-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list"]

```
## Non-Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: role-secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-role-secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]

```