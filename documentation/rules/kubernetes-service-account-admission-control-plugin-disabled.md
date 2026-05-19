---
title: "Service account admission control plugin disabled"
group_id: "Kubernetes"
meta:
  name: "service_account_admission_control_plugin_disabled"
  id: "kubernetes-service-account-admission-control-plugin-disabled"
  display_name: "Service account admission control plugin disabled"
  cloud_provider: ""
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-service-account-admission-control-plugin-disabled{{< /copyable-code >}}

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