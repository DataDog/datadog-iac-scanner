---
title: "Kubelet client periodic certificate switch disabled"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/kubelet_client_periodic_certificate_switch_disabled"
  id: "52d70f2e-3257-474c-b3dc-8ad9ba6a061a"
  display_name: "Kubelet client periodic certificate switch disabled"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `52d70f2e-3257-474c-b3dc-8ad9ba6a061a`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/)

### Description

The kubelet argument `--rotate-certificates` should be set to `true`.
This rule flags kubelet containers (`containers` or `initContainers`) whose command is `kubelet` and include `--rotate-certificates=false`, and KubeletConfiguration resources where `rotateCertificates` is `false` or not set (default is false).
Enabling certificate rotation allows automatic renewal of kubelet client certificates and prevents certificate expiration-related failures.

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
      args: ["--rotate-certificates"]
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
rotateCertificates: true

```

```json
{
    "port": 20250,
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "kind": "KubeletConfiguration",
    "rotateCertificates": true,
    "serializeImagePulls": false,
    "address": "192.168.0.8",
    "apiVersion": "kubelet.config.k8s.io/v1beta1"
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
rotateCertificates: false

```

```json
{
    "port": 20250,
    "evictionHard": {
        "memory.available": "200Mi"
    },
    "kind": "KubeletConfiguration",
    "makeIPTablesUtilChains": true,
    "address": "192.168.0.8",
    "apiVersion": "kubelet.config.k8s.io/v1beta1"
}

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