---
title: "Image policy webhook admission control plugin not set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/image_policy_webhook_admission_control_plugin_not_set"
  id: "14abda69-8e91-4acb-9931-76e2bee90284"
  display_name: "Image policy webhook admission control plugin not set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `14abda69-8e91-4acb-9931-76e2bee90284`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When running `kube-apiserver`, the `--enable-admission-plugins` flag should include `ImagePolicyWebhook`, and the plugin must be configured in the admission control configuration file so it is operational. If the `--enable-admission-plugins` flag does not contain `ImagePolicyWebhook`, this rule reports a missing attribute for the `kube-apiserver` container.

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
      args: ["--enable-admission-plugins=ImagePolicyWebhook", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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
      command: ["kube-apiserver","--enable-admission-plugins=ImagePolicyWebhook", "--admission-control-config-file=path/to/plugin/config/file.yaml"]
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