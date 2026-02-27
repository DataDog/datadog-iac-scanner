---
title: "RBAC wildcard in rule"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/rbac_wildcard_in_rule"
  id: "6b896afb-ca07-467a-b256-1a0077a1c08e"
  display_name: "RBAC wildcard in rule"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `6b896afb-ca07-467a-b256-1a0077a1c08e`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Description

Roles and ClusterRoles with wildcard RBAC permissions grant excessive rights to the Kubernetes API and should be avoided. This rule flags Role and ClusterRole resources where any rule uses the wildcard "*" in the `apiGroups`, `resources`, or `verbs` fields. Wildcards permit broad access across API groups, resources, or actions, which can lead to privilege escalation or unintended access. The principle of least privilege recommends listing only the specific resources and actions required and reviewing existing rules to remove unnecessary wildcards.

## Compliant Code Examples
```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: opa
  name: configmap-modifier
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["update", "patch"]
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: opa
  name: configmap-modifier
rules:
- apiGroups: [""]
  resources: ["searchmaps"]
  verbs: ["create", "patch"]
```
## Non-Compliant Code Examples
```yaml
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: rbac1
  name: configmap-modifier
rules:
- apiGroups: ["*"]
  resources: ["configmaps"]
  verbs: ["*"]
---
# Define role for OPA/kube-mgmt to update configmaps with policy status.
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: rbac2
  name: configmap-modifier1
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: rbac3
  name: configmap-modifier2
rules:
- operations: ["CREATE", "UPDATE"]
  apiGroups: ["*"]
  apiVersions: ["*"]
  resources: ["*"]
  verbs: ["POST"]

```