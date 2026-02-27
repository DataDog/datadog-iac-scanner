---
title: "Container running as root"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/containers_running_as_root"
  id: "cf34805e-3872-4c08-bf92-6ff7bb0cfadb"
  display_name: "Container running as root"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `cf34805e-3872-4c08-bf92-6ff7bb0cfadb`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

### Description

Containers should run as a non-root user. This rule checks `securityContext.runAsUser` and `securityContext.runAsNonRoot` at both the container and pod levels (including inherited settings) and requires `runAsUser` > 0 and/or `runAsNonRoot` = true. Running as non-root reduces the exploitability of security misconfigurations and limits an attacker's options if a container is compromised.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo-2
spec:
  securityContext:
    runAsUser: 10000
    runAsNonRoot: true
  containers:
  - name: sec-ctx-demo-2
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 10100
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo-1
spec:
  securityContext:
    runAsUser: 1000
    runAsNonRoot: true
  containers:
  - name: sec-ctx-demo-100
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 1000
      runAsNonRoot: false
  - name: sec-ctx-demo-200
    image: gcr.io/google-samples/node-hedwfwllo:1.0
    securityContext:
      runAsUser: 2000
      runAsNonRoot: true
      
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: containers-runs-as-root
spec:
  securityContext:
    runAsUser: 0
    runAsNonRoot: false
  containers:
  - name: sec-ctx-demo-100
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 1000
      runAsNonRoot: false
      
```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo-2
spec:
  securityContext:
    runAsUser: 10
    runAsNonRoot: false
  containers:
  - name: sec-ctx-demo-100
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 0
      runAsNonRoot: false
  - name: sec-ctx-demo-200
    image: gcr.io/google-samples/node-hedwfwllo:1.0
    securityContext:
      runAsUser: 0
      runAsNonRoot: false
      
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: containers-runs-as-root
spec:
  securityContext:
    runAsUser: 0
    runAsNonRoot: false
  containers:
  - name: sec-ctx-demo-100
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 0
      runAsNonRoot: false
      
      
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo-2
spec:
  containers:
  - name: sec-ctx-demo-1
    image: gcr.io/google-samples/node-hello:1.0
  - name: sec-ctx-demo-2
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      runAsUser: 0
      allowPrivilegeEscalation: false
      runAsNonRoot: false

```