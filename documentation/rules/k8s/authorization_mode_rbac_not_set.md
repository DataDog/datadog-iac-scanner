---
title: "Authorization mode RBAC not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/authorization_mode_rbac_not_set"
  id: "1aa4a1ae-5dbb-48a1-9aa2-630ea4be208e"
  display_name: "Authorization mode RBAC not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `1aa4a1ae-5dbb-48a1-9aa2-630ea4be208e`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

Resources that run `kube-apiserver` should set the `--authorization-mode` flag to include `RBAC`. If `--authorization-mode=RBAC` is not present, RBAC authorization will not be enforced and access control may be insufficient. This rule checks `containers` and `initContainers` commands for `kube-apiserver` and flags those missing the `--authorization-mode` `RBAC` mode.

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
      args: ["--authorization-mode=Node"]
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