---
title: "Readiness probe is not configured"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/readiness_probe_is_not_configured"
  id: "a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3"
  display_name: "Readiness probe is not configured"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** `a659f3b5-9bf0-438a-bd9a-7d3a6427f1e3`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-readiness-probes)

### Description

 Each container should define a `readinessProbe`. This rule flags containers that do not have the `readinessProbe` attribute set (excludes resources of kind Job and CronJob). A configured `readinessProbe` lets the kubelet determine when a pod is ready to receive traffic.


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
    ports:
    - containerPort: 8080
    readinessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 10
    livenessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 20

```
## Non-Compliant Code Examples
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
    ports:
    - containerPort: 8080
    livenessProbe:
      tcpSocket:
        port: 8080
      initialDelaySeconds: 15
      periodSeconds: 20

```