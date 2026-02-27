---
title: "Kubelet not managing IP tables"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_not_managing_ip_tables"
  id: "5f89001f-6dd9-49ff-9b15-d8cd71b617f4"
  display_name: "Kubelet not managing IP tables"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `5f89001f-6dd9-49ff-9b15-d8cd71b617f4`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/)

### Description

The kubelet argument `--make-iptables-util-chains` should be set to `true`. This policy identifies kubelet invocations that explicitly include `--make-iptables-util-chains=false` (for example in `initContainers` or `containers` command arrays) or `KubeletConfiguration` resources where `makeIPTablesUtilChains` is set to `false`. Disabling this option prevents the kubelet from creating required iptables utility chains, which can disrupt network routing and kube-proxy behavior.

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
      args: ["--make-iptables-util-chains=true"]
  restartPolicy: OnFailure

```

```json
{
    "port": 20250,
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "kind": "KubeletConfiguration",
    "makeIPTablesUtilChains": true,
    "serializeImagePulls": false,
    "address": "192.168.0.8",
    "apiVersion": "kubelet.config.k8s.io/v1beta1"
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
      args: [""]
  restartPolicy: OnFailure

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
makeIPTablesUtilChains: false

```

```json
{
    "apiVersion": "kubelet.config.k8s.io/v1beta1",
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "kind": "KubeletConfiguration",
    "makeIPTablesUtilChains": false,
    "port": 20250,
    "serializeImagePulls": false,
    "address": "192.168.0.8"
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
      args: ["--make-iptables-util-chains=false"]
  restartPolicy: OnFailure

```