---
title: "Root container not mounted as read-only"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/root_container_not_mounted_as_read_only"
  id: "a9c2f49d-0671-4fc9-9ece-f4e261e128d0"
  display_name: "Root container not mounted as read-only"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `a9c2f49d-0671-4fc9-9ece-f4e261e128d0`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

### Description

The root container filesystem should be mounted as read-only. This rule checks both `containers` and `initContainers` and expects `securityContext.readOnlyRootFilesystem` to be set to `true` for each container. It reports `IncorrectValue` when the field is present and `false`, and `MissingAttribute` when the field is undefined.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: goproxy
  labels:
    app: goproxy
spec:
  containers:
  - name: goproxy
    image: k8s.gcr.io/goproxy:0.1
    securityContext:
      readOnlyRootFilesystem: true

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: rootfalse
  labels:
    app: goproxy
spec:
  containers:
  - name: contain1_1
    image: k8s.gcr.io/goproxy:0.1
    securityContext:
      readOnlyRootFilesystem: false
---
apiVersion: v1
kind: Pod
metadata:
  name: noroot
  labels:
    app: goproxy
spec:
  containers:
  - name: contain1_2
    image: k8s.gcr.io/goproxy:0.1
    securityContext:
      someotherthing: true
```