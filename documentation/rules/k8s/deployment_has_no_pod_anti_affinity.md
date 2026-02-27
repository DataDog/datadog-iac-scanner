---
title: "Deployment without podAntiAffinity"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/deployment_has_no_pod_anti_affinity"
  id: "a31b7b82-d994-48c4-bd21-3bab6c31827a"
  display_name: "Deployment without podAntiAffinity"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `a31b7b82-d994-48c4-bd21-3bab6c31827a`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/)

### Description

Deployments with more than two replicas should include a `podAntiAffinity` policy to prevent multiple Pods from being scheduled on the same node. The policy must be defined under `spec.template.spec.affinity.podAntiAffinity` and include at least one of `preferredDuringSchedulingIgnoredDuringExecution` or `requiredDuringSchedulingIgnoredDuringExecution`. Each affinity term's `podAffinityTerm.topologyKey` must be set to 'kubernetes.io/hostname', and its `labelSelector.matchLabels` must match labels on the pod template.

## Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-server
spec:
  selector:
    matchLabels:
      app: web-store
  replicas: 3
  template:
    metadata:
      labels:
        app: web-store
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - web-store
            topologyKey: "kubernetes.io/hostname"
      containers:
      - name: web-app
        image: nginx:1.16-alpine
```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: label-mismatch
spec:
  selector:
    matchLabels:
      app: web-store
  replicas: 3
  template:
    metadata:
      labels:
        app: web-shore
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: web-store
            topologyKey: "kubernetes.io/hostname"
      containers:
      - name: web-app
        image: nginx:1.16-alpine
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-affinity
spec:
  selector:
    matchLabels:
      app: web-store
  replicas: 3
  template:
    metadata:
      labels:
        app: web-store
    spec:
      containers:
      - name: web-app
        image: nginx:1.16-alpine

```