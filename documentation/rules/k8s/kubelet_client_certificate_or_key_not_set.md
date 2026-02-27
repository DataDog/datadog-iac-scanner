---
title: "Kubelet client certificate or key not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_client_certificate_or_key_not_set"
  id: "36a27826-1bf5-49da-aeb0-a60a30c0e834"
  display_name: "Kubelet client certificate or key not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `36a27826-1bf5-49da-aeb0-a60a30c0e834`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When a container runs `kube-apiserver`, the `--kubelet-client-key` and `--kubelet-client-certificate` flags should be set. These flags configure the TLS client certificate and key the kube-apiserver uses to authenticate to kubelets; omitting them may prevent secure communication with kubelets. This rule checks both `containers` and `initContainers` for a `kube-apiserver` command and reports when one or both flags are not present in the command arguments.

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
      command: ["kube-apiserver", "--kubelet-client-certificate=/path/to/any/file.pem", "--kubelet-client-key=/path/to/any/file2.pem"]
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
      args: ["--kubelet-client-certificate=/path/to/any/file.pem", "--kubelet-client-key=/path/to/any/file2"]
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
      args: ["--kubelet-client-certificate=/path/to/any/file.pem"]
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
      args: ["--kubelet-client-key=/path/to/any/file"]
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
  restartPolicy: OnFailure

```