---
title: "Kubelet hostname override is set"
group_id: "Kubernetes"
meta:
  name: "kubelet_hostname_override_is_set"
  id: "kubernetes-kubelet-hostname-override-is-set"
  display_name: "Kubelet hostname override is set"
  cloud_provider: ""
  platform: "Kubernetes"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-kubelet-hostname-override-is-set{{< /copyable-code >}}

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