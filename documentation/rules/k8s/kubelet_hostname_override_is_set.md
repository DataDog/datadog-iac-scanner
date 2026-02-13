---
title: "Kubelet hostname override is set"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_hostname_override_is_set"
  id: "bf36b900-b5ef-4828-adb7-70eb543b7cfb"
  display_name: "Kubelet hostname override is set"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `bf36b900-b5ef-4828-adb7-70eb543b7cfb`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/)

### Description

 Hostnames should not be overridden.
This rule detects containers (including `initContainers`) whose command invokes `kubelet` and includes the `--hostname-override=` flag.
Overriding the node hostname can create duplicate or incorrect hostnames and may disrupt node identity and cluster operations.


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
      image: foo/bar
      command: ["kubelet"]
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
      image: foo/bar
      command: ["kubelet","--hostname-override=host"]
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
      image: foo/bar
      command: ["kubelet"]
      args: ["--hostname-override=host"]
  restartPolicy: OnFailure

```