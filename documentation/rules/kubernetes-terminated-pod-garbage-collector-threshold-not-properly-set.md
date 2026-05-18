---
title: "Terminated pod garbage collector threshold not properly set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "kubernetes/terminated_pod_garbage_collector_threshold_not_properly_set"
  id: "kubernetes-terminated-pod-garbage-collector-threshold-not-properly-set"
  display_name: "Terminated pod garbage collector threshold not properly set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Availability"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-terminated-pod-garbage-collector-threshold-not-properly-set{{< /copyable-code >}}

**Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Availability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)

### Description

For containers running `kube-controller-manager`, the `--terminated-pod-gc-threshold` flag must be set to a value between `0` and `12501`. The rule checks the `command` fields in both `initContainers` and `containers` and reports when the flag is missing or set to an incorrect value.

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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager"]
      args: ["--terminated-pod-gc-threshold=10"]
  restartPolicy: OnFailure

```

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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager","--terminated-pod-gc-threshold=10"]
      args: []
  restartPolicy: OnFailure

```
## Non-Compliant Code Examples
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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager"]
      args: ["--terminated-pod-gc-threshold=12501"]
  restartPolicy: OnFailure

```

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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager","--terminated-pod-gc-threshold=0"]
      args: []
  restartPolicy: OnFailure

```