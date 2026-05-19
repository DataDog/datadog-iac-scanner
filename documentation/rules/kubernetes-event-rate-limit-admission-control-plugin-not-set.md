---
title: "Event rate limit admission control plugin not set"
group_id: "Kubernetes"
meta:
  name: "event_rate_limit_admission_control_plugin_not_set"
  id: "kubernetes-event-rate-limit-admission-control-plugin-not-set"
  display_name: "Event rate limit admission control plugin not set"
  cloud_provider: ""
  platform: "Kubernetes"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-event-rate-limit-admission-control-plugin-not-set{{< /copyable-code >}}

**Platform:** Kubernetes

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When `kube-apiserver` is used, the `--enable-admission-plugins` flag should include `EventRateLimit`. The admission control configuration file must also contain the corresponding `EventRateLimit` configuration. This rule checks the `containers` and `initContainers` command lines for `kube-apiserver` and reports a MissingAttribute if `EventRateLimit` is absent.

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
      args: ["--enable-admission-plugins=EventRateLimit", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      args: ["--enable-admission-plugins=AlwaysAdmit"]
  restartPolicy: OnFailure

```