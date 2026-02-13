---
title: "Service account admission control plugin disabled"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/service_account_admission_control_plugin_disabled"
  id: "9587c890-0524-40c2-9ce2-663af7c2f063"
  display_name: "Service account admission control plugin disabled"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `9587c890-0524-40c2-9ce2-663af7c2f063`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When `kube-apiserver` is used, the `--disable-admission-plugins` flag should not include the `ServiceAccount` plugin. Disabling the `ServiceAccount` admission plugin prevents the API server from admitting service account tokens and can break pod authentication and credential provisioning. This rule detects `kube-apiserver` containers and examines the container command for the `--disable-admission-plugins` flag containing `ServiceAccount`.

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
      args: ["--enable-admission-plugins=ServiceAccount", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      command: ["kube-apiserver","--disable-admission-plugins=ServiceAccount"]
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
      command: ["kube-apiserver"]
      args: ["--disable-admission-plugins=ServiceAccount"]
  restartPolicy: OnFailure

```