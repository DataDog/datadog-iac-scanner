---
title: "etcd client certificate file not defined"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/etcd_client_certificate_file_not_defined"
  id: "3f5ff8a7-5ad6-4d02-86f5-666307da1b20"
  display_name: "etcd client certificate file not defined"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `3f5ff8a7-5ad6-4d02-86f5-666307da1b20`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

 When the `kube-apiserver` process is present in a Pod's `containers` or `initContainers`, the `--etcd-cafile` flag should be set. The rule detects `kube-apiserver` in container command arrays and reports resources where the `--etcd-cafile` flag is not defined. Setting `--etcd-cafile` ensures the API server verifies etcd's CA certificate.


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
      args: ["--etcd-cafile=/path/to/ca/file.pem"]
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
      command: ["kube-apiserver","--etcd-cafile=/path/to/ca/file.pem"]
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
      args: []
  restartPolicy: OnFailure

```