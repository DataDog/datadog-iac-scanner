---
title: "Authorization mode node not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/authorization_mode_node_not_set"
  id: "4d7ee40f-fc5d-427d-8cac-dffbe22d42d1"
  display_name: "Authorization mode node not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `4d7ee40f-fc5d-427d-8cac-dffbe22d42d1`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When a container runs `kube-apiserver`, the `--authorization-mode` flag should include `Node`. This rule applies to both `containers` and `initContainers` and inspects the container `command` to verify the presence of `--authorization-mode` with the `Node` value. Omission of `Node` from `--authorization-mode` may disable node-level authorization and increase the API server's security risk.

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
      args: ["--authorization-mode=RBAC,Node"]
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
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver","--authorization-mode=RBAC,Node"]
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
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver"]
      args: ["--authorization-mode=RBAC"]
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
      image: gcr.io/google_containers/kube-apiserver-amd64:v1.6.0
      command: ["kube-apiserver"]
      args: ["--authorization-mode=AlwaysAllow"]
  restartPolicy: OnFailure

```