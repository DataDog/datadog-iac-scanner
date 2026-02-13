---
title: "Encryption provider config is not defined"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/encryption_provider_config_is_not_defined"
  id: "cbd2db69-0b21-4c14-8a40-7710a50571a9"
  display_name: "Encryption provider config is not defined"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `cbd2db69-0b21-4c14-8a40-7710a50571a9`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When `kube-apiserver` is used, the `--encryption-provider-config` flag should be set, and the referenced encryption configuration file should correctly configure encryption providers. This rule checks `containers` and `initContainers` for `kube-apiserver` command invocations and reports when the `--encryption-provider-config` flag is not present. Missing this flag and a valid encryption config can result in secrets and other sensitive data being stored unencrypted at rest.

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
      args: ["--encryption-provider-config=/path/to/config/file.yaml"]
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
      command: ["kube-apiserver","--encryption-provider-config=/path/to/config/file.yaml"]
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