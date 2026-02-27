---
title: "Pod or container without security context"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/pod_or_container_without_security_context"
  id: "a97a340a-0063-418e-b3a1-3028941d0995"
  display_name: "Pod or container without security context"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `a97a340a-0063-418e-b3a1-3028941d0995`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

### Description

A security context defines privilege and access control settings for a Pod or container. This policy requires that a Pod's spec include a `securityContext` and that each container in `containers` and `initContainers` include a `securityContext`. The rule flags Pod resources and individual containers missing a `securityContext`, since absent contexts can allow containers to run with default or elevated privileges and increase security risk.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
spec:
  securityContext:
    runAsUser: 1000
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
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
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
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
```