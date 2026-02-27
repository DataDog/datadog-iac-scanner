---
title: "Service account private key file not defined"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/service_account_private_key_file_not_defined"
  id: "ccc98ff7-68a7-436e-9218-185cb0b0b780"
  display_name: "Service account private key file not defined"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Encryption"
---
## Metadata

**Id:** `ccc98ff7-68a7-436e-9218-185cb0b0b780`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)

### Description

When `kube-controller-manager` is used, the `--service-account-private-key-file` flag should be set. This rule checks the `containers` and `initContainers` `command` fields for `kube-controller-manager` and verifies the presence of the `--service-account-private-key-file` flag. Setting this flag ensures the controller manager has a private key to sign service account tokens.

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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager"]
      args: ["--service-account-private-key-file=/path/to/key/file.pem"]
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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager","--service-account-private-key-file=/path/to/key/file.pem"]
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
      image: gcr.io/google_containers/kube-controller-manager-amd64:v1.6.0
      command: ["kube-controller-manager"]
      args: []
  restartPolicy: OnFailure

```