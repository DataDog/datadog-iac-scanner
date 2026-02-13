---
title: "Service account lookup set to false"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/service_account_lookup_set_to_false"
  id: "a5530bd7-225a-48f9-91bb-f40b04200165"
  display_name: "Service account lookup set to false"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `a5530bd7-225a-48f9-91bb-f40b04200165`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)

### Description

When using `kube-apiserver`, the `--service-account-lookup` flag should be set to `true`. This rule flags containers (including `initContainers`) that run `kube-apiserver` and explicitly set `--service-account-lookup=false`. Disabling this lookup skips verification that a token's service account still exists, which can allow tokens for deleted or revoked service accounts to be accepted; therefore the flag should be enabled (`true`).

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
      args: ["--service-account-lookup=true"]
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
      command: ["kube-apiserver"]
      args: ["--service-account-lookup=false"]
  restartPolicy: OnFailure

```