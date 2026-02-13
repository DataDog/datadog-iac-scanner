---
title: "Secure port set to zero"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/secure_port_set_to_zero"
  id: "3d24b204-b73d-42cb-b0bf-1a5438c5f71e"
  display_name: "Secure port set to zero"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `3d24b204-b73d-42cb-b0bf-1a5438c5f71e`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

 When using `kube-apiserver`, the `--secure-port` flag should not be set to `0`. Setting `--secure-port=0` disables the API server's secure (HTTPS) listener, which can prevent encrypted communication and potentially expose the server to insecure access. This rule inspects container command arguments in `containers` and `initContainers` for `kube-apiserver` and flags any occurrence of `--secure-port=0`.


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
      args: []
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
      command: ["kube-apiserver","--secure-port=6443"]
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
      args: ["--secure-port=0"]
  restartPolicy: OnFailure

```