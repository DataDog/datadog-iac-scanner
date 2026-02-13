---
title: "Service account key file not properly set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/service_account_key_file_not_properly_set"
  id: "dab4ec72-ce2e-4732-b7c3-1757dcce01a1"
  display_name: "Service account key file not properly set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `dab4ec72-ce2e-4732-b7c3-1757dcce01a1`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

 When a container runs `kube-apiserver`, the `--service-account-key-file` flag should be set to a PEM-encoded key file. This enables the API server to validate service account tokens presented to it. The rule flags `kube-apiserver` containers that do not include this flag.


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
      args: ["--service-account-key-file=/path/to/file.pem"]
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