---
title: "PSP with unrestricted access to host path"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/psp_with_unrestricted_access_to_host_path"
  id: "de4421f1-4e35-43b4-9783-737dd4e4a47e"
  display_name: "PSP with unrestricted access to host path"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Resource Management"
---
## Metadata

**Id:** `de4421f1-4e35-43b4-9783-737dd4e4a47e`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems)

### Description

PodSecurityPolicy should set `readOnly` to `true` for every entry in `spec.allowedHostPaths`. The `spec.allowedHostPaths` attribute must be defined and not null, and each allowed host path must include `readOnly: true`. Entries with `readOnly` undefined or set to `false`, or a missing `spec.allowedHostPaths`, are reported.

## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  hostIPC: false
  allowedHostPaths:
    - pathPrefix: "/foo"
      readOnly: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

```
## Non-Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  hostIPC: false
  allowedHostPaths:
  - pathPrefix: /dev
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

```

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  hostIPC: false
  allowedHostPaths:
  - pathPrefix: /etc
    readOnly: true
  - pathPrefix: /dev
    readOnly: false
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

```

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  hostIPC: false
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

```