---
title: "Security context deny admission control plugin not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/security_context_deny_admission_control_plugin_not_set"
  id: "6a68bebe-c021-492e-8ddb-55b0567fb768"
  display_name: "Security context deny admission control plugin not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `6a68bebe-c021-492e-8ddb-55b0567fb768`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

For `kube-apiserver`, the `--enable-admission-plugins` flag should include `SecurityContextDeny` when `PodSecurityPolicy` is not set. The `SecurityContextDeny` plugin must also be configured in the admission control configuration file. This ensures pod security constraints remain enforced when `PodSecurityPolicy` is disabled. The rule checks both `containers` and `initContainers` command lines for the presence of the flag and plugin.

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
      args: ["--enable-admission-plugins=SecurityContextDeny", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      command: ["kube-apiserver","--enable-admission-plugins=SecurityContextDeny", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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