---
title: "etcd TLS certificate not properly configured"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "kubernetes/etcd_tls_certificate_not_properly_configured"
  id: "kubernetes-etcd-tls-certificate-not-properly-configured"
  display_name: "etcd TLS certificate not properly configured"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-etcd-tls-certificate-not-properly-configured{{< /copyable-code >}}

**Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When using `kube-apiserver`, the `--etcd-certfile` and `--etcd-keyfile` flags should be set. The rule checks `containers` and `initContainers` for containers whose command includes `kube-apiserver` and reports a MissingAttribute issue when either flag is not defined.

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
      args: ["--etcd-keyfile=/path/to/key/file.key","--etcd-certfile=/path/to/cert/file.crt"]
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
      command: ["kube-apiserver","--etcd-keyfile=/path/to/key/file.key","--etcd-certfile=/path/to/cert/file.crt"]
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
      args: ["--etcd-certfile=/path/to/cert/file.crt"]
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
      args: ["--etcd-keyfile=/path/to/key/file.key"]
  restartPolicy: OnFailure

```