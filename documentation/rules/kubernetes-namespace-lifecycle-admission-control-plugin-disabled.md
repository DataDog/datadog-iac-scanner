---
title: "Namespace lifecycle admission control plugin disabled"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "kubernetes/namespace_lifecycle_admission_control_plugin_disabled"
  id: "kubernetes-namespace-lifecycle-admission-control-plugin-disabled"
  display_name: "Namespace lifecycle admission control plugin disabled"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-namespace-lifecycle-admission-control-plugin-disabled{{< /copyable-code >}}

**Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When running `kube-apiserver`, the `--disable-admission-plugins` flag should not include the `NamespaceLifecycle` plugin. Disabling the `NamespaceLifecycle` admission plugin can bypass namespace lifecycle checks and may lead to orphaned resources or unexpected behavior across namespaces. This rule identifies `kube-apiserver` containers and flags any `--disable-admission-plugins` setting that contains `NamespaceLifecycle`.

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
      args: ["--enable-admission-plugins=NamespaceLifecycle", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      command: ["kube-apiserver","--disable-admission-plugins=NamespaceLifecycle"]
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
      args: ["--disable-admission-plugins=NamespaceLifecycle"]
  restartPolicy: OnFailure

```