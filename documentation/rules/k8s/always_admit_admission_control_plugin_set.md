---
title: "Always admit admission control plugin set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/always_admit_admission_control_plugin_set"
  id: "ce30e584-b33f-4c7d-b418-a3d7027f8f60"
  display_name: "Always admit admission control plugin set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `ce30e584-b33f-4c7d-b418-a3d7027f8f60`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When the `kube-apiserver` command is present, the `--enable-admission-plugins` flag should not include the `AlwaysAdmit` plugin. This rule identifies `containers` and `initContainers` running `kube-apiserver` and flags resources whose `--enable-admission-plugins` flag contains `AlwaysAdmit`. The `AlwaysAdmit` plugin bypasses admission control and allows requests without validation, so it should not be used in production.

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
      command: ["kube-apiserver","--enable-admission-plugins=EventRateLimit", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      args: ["--enable-admission-plugins=AlwaysAdmit", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
  restartPolicy: OnFailure

```