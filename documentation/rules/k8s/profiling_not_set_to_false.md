---
title: "Profiling not set to false"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/profiling_not_set_to_false"
  id: "2f491173-6375-4a84-b28e-a4e2b9a58a69"
  display_name: "Profiling not set to false"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `2f491173-6375-4a84-b28e-a4e2b9a58a69`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When using `kube-apiserver`, `kube-controller-manager`, or `kube-scheduler`, the `--profiling` flag should be set to `false`. If the flag is present and set to `true`, it is reported as an incorrect value. If the flag is missing on applicable components, it is reported as a missing attribute. The `KubeSchedulerConfiguration` document's `enableProfiling` field must also be present and set to `false`.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: command-demo
  labels:
    purpose: demonstrate-command
spec:
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver"]
      args: ["--profiling=false"]
  restartPolicy: OnFailure

```

```yaml
apiVersion: kubescheduler.config.k8s.io/v1beta2
kind: KubeSchedulerConfiguration
enableProfiling: false
profiles:
- pluginConfig:
  - args:
      scoringStrategy:
        resources:
        - name: cpu
          weight: 1
        type: MostAllocated
    name: NodeResourcesFit3

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    component: kube-scheduler
    tier: control-plane
  name: kube-scheduler-master-1
  namespace: kube-system
spec:
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-scheduler-master-1
      command: ["kube-scheduler"]
      args: []
  restartPolicy: OnFailure

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: command-demo-1
  labels:
    purpose: demonstrate-command
spec:
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver"]
      args: []
  restartPolicy: OnFailure

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    component: kube-controller-manager
    tier: control-plane
  name: kube-controller-manager-master-3
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: kube-controller-manager
  template:
    metadata:
      labels:
        app: kube-controller-manager
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-controller-manager-master-3
      command: ["kube-controller-manager","--profiling=true"]
      args: []
  restartPolicy: OnFailure

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  creationTimestamp: null
  labels:
    component: kube-controller-manager
    tier: control-plane
  name: kube-controller-manager-master-4
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: kube-controller-manager
  template:
    metadata:
      labels:
        app: kube-controller-manager
  containers:
    - name: command-demo-container
      image: gcr.io/google_containers/kube-controller-manager-master-4
      command: ["kube-controller-manager"]
      args: []
  restartPolicy: OnFailure

```