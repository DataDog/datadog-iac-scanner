---
title: "PSP allows sharing host IPC"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/psp_allows_sharing_host_ipc"
  id: "80f93444-b240-4ebb-a4c6-5c40b76c04ea"
  display_name: "PSP allows sharing host IPC"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `80f93444-b240-4ebb-a4c6-5c40b76c04ea`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

### Description

 PodSecurityPolicy 'spec.hostIPC' allows containers to share the host IPC namespace when set to true. Sharing the host IPC namespace lets processes in a container observe or interfere with IPC resources of other containers or the host, increasing the risk of information disclosure and privilege escalation. 'spec.hostIPC' should be set to false or left undefined to preserve IPC isolation.


## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  hostIPC: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny

```
## Non-Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  hostIPC: true
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny

```