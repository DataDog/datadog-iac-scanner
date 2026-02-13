---
title: "Kubelet streaming connection timeout disabled"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_streaming_connection_timeout_disabled"
  id: "ed89b97d-04e9-4fd4-919f-ee5b27e555e9"
  display_name: "Kubelet streaming connection timeout disabled"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `ed89b97d-04e9-4fd4-919f-ee5b27e555e9`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/)

### Description

 The `--streaming-connection-idle-timeout` flag should not be set to `0`. The rule also checks container `command` entries in `containers` and `initContainers`, and the `KubeletConfiguration` field `streamingConnectionIdleTimeout` should not be set to `0s`. Setting the timeout to zero disables the idle timeout and can allow connections to remain open indefinitely, increasing the risk of resource exhaustion or unintended exposure.


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
      args: [""]
  restartPolicy: OnFailure

```

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: "192.168.0.8"
port: 20250
serializeImagePulls: false
evictionHard:
    memory.available:  "200Mi"

```

```json
{
    "address": "192.168.0.8",
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "kind": "KubeletConfiguration",
    "port": 20250,
    "serializeImagePulls": false
}

```
## Non-Compliant Code Examples
```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
address: "192.168.0.8"
port: 20250
serializeImagePulls: false
evictionHard:
    memory.available:  "200Mi"
streamingConnectionIdleTimeout: 0s

```

```json
{
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "kind": "KubeletConfiguration",
    "serializeImagePulls": false,
    "address": "192.168.0.8",
    "port": 20250,
    "streamingConnectionIdleTimeout": "0s"
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
      command: ["kubelet"]
      args: ["--streaming-connection-idle-timeout=0"]
  restartPolicy: OnFailure

```