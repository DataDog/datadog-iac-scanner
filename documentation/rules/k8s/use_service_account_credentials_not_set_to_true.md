---
title: "Use service account credentials not set to true"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/use_service_account_credentials_not_set_to_true"
  id: "1acd93f1-5a37-45c0-aaac-82ece818be7d"
  display_name: "Use service account credentials not set to true"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `1acd93f1-5a37-45c0-aaac-82ece818be7d`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/)

### Description

When running `kube-controller-manager`, the `--use-service-account-credentials` flag should be set to `true`. If the flag is set to `false` or omitted, the controller manager will not use service account credentials to authenticate to the API server, which can cause controllers to operate with incorrect or elevated permissions. This rule reports `IncorrectValue` when the flag is explicitly set to `false` and `MissingAttribute` when the flag is not present.

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
      args: ["--use-service-account-credentials=true"]
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
      command: ["kube-controller-manager","--use-service-account-credentials=true"]
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
      command: ["kube-controller-manager","--use-service-account-credentials=false"]
      args: []
  restartPolicy: OnFailure

```