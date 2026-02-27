---
title: "PSP allows privilege escalation"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/psp_allows_privilege_escalation"
  id: "87554eef-154d-411d-bdce-9dbd91e56851"
  display_name: "PSP allows privilege escalation"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `87554eef-154d-411d-bdce-9dbd91e56851`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

### Description

PodSecurityPolicy should not allow privilege escalation. The PodSecurityPolicy must include the 'allowPrivilegeEscalation' attribute and it must be set to false. If the attribute is missing or set to true, the PodSecurityPolicy is considered non-compliant.

## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: false
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
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
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'

---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged2
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```