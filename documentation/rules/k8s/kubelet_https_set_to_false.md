---
title: "Kubelet HTTPS set to false"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_https_set_to_false"
  id: "kubernetes-kubelet-https-set-to-false"
  display_name: "Kubelet HTTPS set to false"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `kubernetes-kubelet-https-set-to-false`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When using `kube-apiserver`, the `--kubelet-https` flag should be set to `true` or omitted; it must not be set to `false`.
This rule checks container and initContainer command arguments for `kube-apiserver` and reports when `--kubelet-https=false` is present.
Setting the flag to `false` disables HTTPS to the kubelet and results in insecure communication; set it to `true` or remove the flag to enforce secure connections.

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
      args: ["--kubelet-https=true"]
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
      args: ["--kubelet-https=false"]
  restartPolicy: OnFailure

```