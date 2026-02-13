---
title: "Role binding to default service account"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/role_binding_to_default_service_account"
  id: "1e749bc9-fde8-471c-af0c-8254efd2dee5"
  display_name: "Role binding to default service account"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Defaults"
---
## Metadata

**Id:** `1e749bc9-fde8-471c-af0c-8254efd2dee5`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Defaults

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)

### Description

No RoleBinding or ClusterRoleBinding should bind to the default ServiceAccount. Binding roles to the default ServiceAccount grants those permissions to all pods that use that account in the namespace, increasing the risk of unintended privilege escalation. This undermines least-privilege principles and can expose workloads to unnecessary privileges.

## Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```
## Non-Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: User
  name: jane
  apiGroup: rbac.authorization.k8s.io
- kind: ServiceAccount
  name: default
  namespace: kube-system
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```