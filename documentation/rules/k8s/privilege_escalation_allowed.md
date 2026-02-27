---
title: "Privilege escalation allowed"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/privilege_escalation_allowed"
  id: "5572cc5e-1e4c-4113-92a6-7a8a3bd25e6d"
  display_name: "Privilege escalation allowed"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `5572cc5e-1e4c-4113-92a6-7a8a3bd25e6d`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

### Description

Containers should not run with the `allowPrivilegeEscalation` attribute set to `true`. The attribute must be present and set to `false` to prevent a container from gaining more privileges than its parent process. This rule applies to both `containers` and `initContainers` and reports missing attributes or values set to `true`.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
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
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example-priv
spec:
  containers:
      - name: payment
        image: nginx
        securityContext:
          capabilities:
          drop:
            - SYS_ADMIN
      - name: payment2
        image: nginx
      - name: payment4
        image: nginx
        securityContext:
          capabilities:
            add:
              - NET_BIND_SERVICE
      - name: payment3
        image: nginx
        securityContext:
          allowPrivilegeEscalation: false

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod2
spec:
  containers:
  - name: app
    image: images.my-company.example/app:v4
    securityContext:
      allowPrivilegeEscalation: true
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
      runAsUser: 2000
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"

```