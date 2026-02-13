---
title: "Kubelet certificate authority not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_certificate_authority_not_set"
  id: "ec18a0d3-0069-4a58-a7fb-fbfe0b4bbbe0"
  display_name: "Kubelet certificate authority not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `ec18a0d3-0069-4a58-a7fb-fbfe0b4bbbe0`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

 When using `kube-apiserver`, the `--kubelet-certificate-authority` flag should be set. The rule checks `containers` and `initContainers` for commands that include `kube-apiserver` and reports when the `--kubelet-certificate-authority` flag is not present. Setting this flag ensures the API server uses the kubelet's certificate authority to validate kubelet TLS connections.


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
      args: ["--kubelet-certificate-authority=/path/to/any/cert/file.pem"]
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
      command: ["kube-apiserver","--kubelet-certificate-authority=/path/to/any/cert/file.crt"]
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
  restartPolicy: OnFailure

```