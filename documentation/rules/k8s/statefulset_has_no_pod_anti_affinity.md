---
title: "StatefulSet without podAntiAffinity"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/statefulset_has_no_pod_anti_affinity"
  id: "d740d048-8ed3-49d3-b77b-6f072f3b669e"
  display_name: "StatefulSet without podAntiAffinity"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `d740d048-8ed3-49d3-b77b-6f072f3b669e`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/)

### Description

StatefulSets should define a `podAntiAffinity` policy to prevent scheduling multiple Pods from the same StatefulSet onto the same node.
The `spec.template.spec.affinity.podAntiAffinity` field must be set with either `preferredDuringSchedulingIgnoredDuringExecution` or `requiredDuringSchedulingIgnoredDuringExecution`. Each term must use `topologyKey: kubernetes.io/hostname` with a label selector that matches the Pod template labels.
This rule applies when `spec.replicas` is greater than 2.

## Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: zk
spec:
  selector:
    matchLabels:
      app: zk
  serviceName: zk-hs
  replicas: 3
  updateStrategy:
    type: RollingUpdate
  podManagementPolicy: OrderedReady
  template:
    metadata:
      labels:
        app: zk
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: zk
              topologyKey: "kubernetes.io/hostname"
      containers:
      - name: kubernetes-zookeeper
        imagePullPolicy: Always
        image: "k8s.gcr.io/kubernetes-zookeeper:1.0-3.4.10"
        resources:
          requests:
            memory: "1Gi"
            cpu: "0.5"
```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: zk-mismatch
spec:
  selector:
    matchLabels:
      app: zk
  serviceName: zk-hs
  replicas: 3
  updateStrategy:
    type: RollingUpdate
  podManagementPolicy: OrderedReady
  template:
    metadata:
      labels:
        app: abc
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: zk
              topologyKey: "kubernetes.io/hostname"
      containers:
      - name: kubernetes-zookeeper
        imagePullPolicy: Always
        image: "k8s.gcr.io/kubernetes-zookeeper:1.0-3.4.10"
        resources:
          requests:
            memory: "1Gi"
            cpu: "0.5"
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: zk-noaffinity
spec:
  selector:
    matchLabels:
      app: zk
  serviceName: zk-hs
  replicas: 3
  updateStrategy:
    type: RollingUpdate
  podManagementPolicy: OrderedReady
  template:
    metadata:
      labels:
        app: zk
    spec:
      affinity:
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - store
            topologyKey: "kubernetes.io/hostname"
      containers:
      - name: kubernetes-zookeeper
        imagePullPolicy: Always
        image: "k8s.gcr.io/kubernetes-zookeeper:1.0-3.4.10"
        resources:
          requests:
            memory: "1Gi"
            cpu: "0.5"
```