---
title: "ServiceAccount allows access to secrets"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/service_account_allows_access_secrets"
  id: "056ac60e-fe07-4acc-9b34-8e1d51716ab9"
  display_name: "ServiceAccount allows access to secrets"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `056ac60e-fe07-4acc-9b34-8e1d51716ab9`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)

### Description

Roles and ClusterRoles that are bound to a ServiceAccount should not include the `get`, `list`, `watch`, or `*` verbs on the `secrets` resource.  
The rule triggers when a Role or ClusterRole contains a rule for the `secrets` resource and a corresponding RoleBinding or ClusterRoleBinding references a ServiceAccount.  
This prevents unintended or broad access to secrets by disallowing these read or wildcard verbs for bound roles.

## Compliant Code Examples
```yaml
# Vulnerable Role Without Binding
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: assembly-prod
  name: testRoleWithoutBindingVulnerable
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
---
# Vulnerable Role With Binding Not Service Account
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: assembly-prod
  name: testRoleWithBindingVulnerableNotSA
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bindingNotSATestRoleWithBindingVulnerable
  namespace: bindingNotSATestRoleWithBindingVulnerableNamespace
subjects:
- kind: NotServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: Role
  name: testRoleWithBindingVulnerableNotSA
  apiGroup: rbac.authorization.k8s.io
---
# Safe Role With Binding
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: assembly-prod
  name: testRoleWithBindingSafe
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["update"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bindingtestRoleWithBindingSafe
  namespace: bindingtestRoleWithBindingSafeNamespace
subjects:
- kind: ServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: Role
  name: testRoleWithBindingSafe
  apiGroup: rbac.authorization.k8s.io
---
# Vulnerable Role with Pod
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: assembly-prod
  name: testRoleVulnerablePod
rules:
- apiGroups: [""]
  resources: ["pod"]
  verbs: ["get", "watch", "list"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: testRoleBinding
  namespace: bindingTestWithBindingPod
subjects:
- kind: ServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: Role
  name: testRoleVulnerablePod
  apiGroup: rbac.authorization.k8s.io
---
# Vulnerable Cluster Role Without Binding
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: testClusterRoleWithoutBindingVulnerable
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
---
# Vulnerable Cluster Role With Binding Not Service Account
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  namespace: default
  name: testClusterRoleWithBindingVulnerableNotSA
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bindingNotSATestClusterRoleWithBindingVulnerable
  namespace: bindingNotSATestClusterRoleWithBindingVulnerableNamespace
subjects:
- kind: NotServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: ClusterRole
  name: testClusterRoleWithBindingVulnerableNotSA
  apiGroup: rbac.authorization.k8s.io
---
# Safe ClusterRole With Binding
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  namespace: default
  name: testClusterRoleWithBindingSafe
rules:
- apiGroups: [""] # "" indicates the core API group
  resources: ["secrets"]
  verbs: ["update"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bindingTestClusterRoleWithBindingSafe
  namespace: bindingTestClusterRoleWithBindingSafeNamespace
subjects:
- kind: NotServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: ClusterRole
  name: testClusterRoleWithBindingSafe
  apiGroup: rbac.authorization.k8s.io
---
# Vulnerable Cluster Role With Pod
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: testClusterRoleVulnerablePod
rules:
- apiGroups: [""]
  resources: ["pod"]
  verbs: ["update", "list"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bindingTestClusterRoleWithBinding
  namespace: bindingTestClusterRoleWithBindingNamespace
subjects:
- kind: ServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: ClusterRole
  name: testClusterRoleVulnerablePod
  apiGroup: rbac.authorization.k8s.io
```
## Non-Compliant Code Examples
```yaml
#Vulnerable Role
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: assembly-prod
  name: testRoleVulnerable
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "watch", "list"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: testRoleBinding
  namespace: bindingTestWithBinding
subjects:
- kind: ServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: Role
  name: testRoleVulnerable
  apiGroup: rbac.authorization.k8s.io
---
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: assembly-prod
  name: testRoleVulnerable2
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["*"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: testRoleBinding
  namespace: bindingTestWithBinding2
subjects:
- kind: ServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: Role
  name: testRoleVulnerable2
  apiGroup: rbac.authorization.k8s.io
---
# Vulnerable Cluster Role
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: testClusterRoleVulnerable
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["update", "list"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: bindingTestClusterRoleWithBinding
  namespace: bindingTestClusterRoleWithBindingNamespace
subjects:
- kind: ServiceAccount
  name: testsa
  apiGroup: ""
roleRef:
  kind: ClusterRole
  name: testClusterRoleVulnerable
  apiGroup: rbac.authorization.k8s.io

```