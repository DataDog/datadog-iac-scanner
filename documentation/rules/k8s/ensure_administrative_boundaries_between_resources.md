---
title: "Ensure administrative boundaries between resources"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/ensure_administrative_boundaries_between_resources"
  id: "e84eaf4d-2f45-47b2-abe8-e581b06deb66"
  display_name: "Ensure administrative boundaries between resources"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Access Control"
---
## Metadata

**Id:** `e84eaf4d-2f45-47b2-abe8-e581b06deb66`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)

### Description

As a best practice, ensure namespaces are used correctly to group and administer resources. Kubernetes authorization mechanisms, such as RBAC, can enforce policies that segregate or restrict user access to namespaces. This rule scans cluster manifests for resources that specify a namespace and aggregates the namespaces in use, reporting them for review. Review the reported namespaces to confirm they are required, appropriately configured, and governed by suitable access controls (for example, RoleBindings, NetworkPolicies, or admission controllers).

## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
  namespace: cosmic-namespace
spec:
  containers:
  - name: app
    image: images.my-company.example/app:v4
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

  - name: log-aggregator
    image: images.my-company.example/log-aggregator:v6
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
---
apiVersion: v1
kind: Pod
metadata:
  name: frontend2
  namespace: cosmic-namespace
spec:
  containers:
  - name: app
    image: images.my-company.example/app:v4
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

  - name: log-aggregator
    image: images.my-company.example/log-aggregator:v6
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"


```