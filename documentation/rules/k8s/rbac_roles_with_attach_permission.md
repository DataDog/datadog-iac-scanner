---
title: "RBAC roles with attach permission"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/rbac_roles_with_attach_permission"
  id: "d45330fd-f58d-45fb-a682-6481477a0f84"
  display_name: "RBAC roles with attach permission"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `d45330fd-f58d-45fb-a682-6481477a0f84`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Description

Roles or ClusterRoles that permit attaching to containers via `kubectl attach` can be abused by attackers to read process output (stdout, stderr) and send input (stdin) to running processes.
They can also allow a malicious user to attach to a privileged container, resulting in privilege escalation.
For this reason, the `pods/attach` resource should not be included in production Role or ClusterRole rules. This rule flags Role or ClusterRole documents whose rules include the `pods/attach` resource (and related verb entries such as `create` or `*`). Findings support least-privilege enforcement by identifying and removing attach permissions from cluster roles.

## Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: my-namespace
  name: allow-attach-neg
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-attach-neg
  namespace: my-namespace
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: allow-attach-neg
  apiGroup: ""

```
## Non-Compliant Code Examples
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: my-namespace
  name: allow-attach
rules:
- apiGroups: [""]
  resources: ["pods", "pods/attach"]
  verbs: ["get", "list", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: allow-attach
  namespace: my-namespace
subjects:
- kind: User
  name: bob
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: allow-attach
  apiGroup: ""

```