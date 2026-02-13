---
title: "Authorization mode set to always allow"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/authorization_mode_set_to_always_allow"
  id: "f1f4d8da-1ac4-47d0-b1aa-91e69d33f7d5"
  display_name: "Authorization mode set to always allow"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `f1f4d8da-1ac4-47d0-b1aa-91e69d33f7d5`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/)

### Description

 When using `kubelet` or `kube-apiserver`, the `--authorization-mode` flag should not be set to `AlwaysAllow`. The rule also checks `KubeletConfiguration` resources and flags an `authorization.mode` equal to `AlwaysAllow`. The `AlwaysAllow` mode grants unrestricted access to all requests and bypasses cluster authorization controls.


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
      args: ["--authorization-mode=MyMode"]
  restartPolicy: OnFailure

```

```json
{
    "kind": "KubeletConfiguration",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "address": "0.0.0.0",
    "authorization": {
      "mode": "webhook"
    }
} 
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
      image: foo/bar
      command: ["kubelet", "--authorization-mode=MyMode"]
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
      command: ["kube-apiserver", "--authorization-mode=MyMode,AlwaysAllow"]
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
      image: foo/bar
      command: ["kubelet"]
      args:
        ["--anonymous-auth=false", "--authorization-mode=MyMode,AlwaysAllow"]
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
      image: foo/bar
      command: ["kubelet", "--authorization-mode=MyMode,AlwaysAllow"]
  restartPolicy: OnFailure

```