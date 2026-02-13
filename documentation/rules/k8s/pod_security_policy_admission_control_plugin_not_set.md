---
title: "Pod security policy admission control plugin not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/pod_security_policy_admission_control_plugin_not_set"
  id: "afa36afb-39fe-4d94-b9b6-afb236f7a03d"
  display_name: "Pod security policy admission control plugin not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Build Process"
---
## Metadata

**Id:** `afa36afb-39fe-4d94-b9b6-afb236f7a03d`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When a `kube-apiserver` container is present (in `containers` or `initContainers`), the `--enable-admission-plugins` flag should include `PodSecurityPolicy`. The rule inspects the container `command` for `kube-apiserver` and reports a MissingAttribute if the flag does not contain `PodSecurityPolicy`. The admission control configuration file should also be correctly configured to enable the plugin.

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
      args: ["--enable-admission-plugins=PodSecurityPolicy", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      command: ["kube-apiserver","--enable-admission-plugins=PodSecurityPolicy", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      args: ["--enable-admission-plugins=AlwaysAdmit"]
  restartPolicy: OnFailure

```