---
title: "PSP allows sharing host PID"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/psp_allows_sharing_host_pid"
  id: "91dacd0e-d189-4a9c-8272-5999a3cc32d9"
  display_name: "PSP allows sharing host PID"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `91dacd0e-d189-4a9c-8272-5999a3cc32d9`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

### Description

PodSecurityPolicy allows containers to share the host process ID namespace when 'spec.hostPID' is true. Sharing the host PID namespace lets containers see and interact with host processes, increasing the risk of information exposure and privilege escalation. This rule flags policies where 'spec.hostPID' is true; it should be false or undefined.

## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  hostPID: false
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
  hostPID: true
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny

```