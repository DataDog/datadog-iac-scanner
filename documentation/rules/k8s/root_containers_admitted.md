---
title: "Root containers admitted"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/root_containers_admitted"
  id: "e3aa0612-4351-4a0d-983f-aefea25cf203"
  display_name: "Root containers admitted"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `e3aa0612-4351-4a0d-983f-aefea25cf203`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

### Description

To ensure containers do not run with root privileges:
- Set `privileged`, `allowPrivilegeEscalation`, and `readOnlyRootFilesystem` to `false`.
- Set `runAsUser.rule` to `MustRunAsNonRoot`.
- Configure `fsGroup` and `supplementalGroups` with `MustRunAs`, ensuring the root range (GID 0) and root group are not permitted.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName:  'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName:  'runtime/default'
spec:
  privileged: false
  # Required to prevent escalations to root.
  allowPrivilegeEscalation: false
  # This is redundant with non-root + disallow privilege escalation,
  # but we can provide it for defense in depth.
  requiredDropCapabilities:
    - ALL
  # Allow core volume types.
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    # Assume that persistentVolumes set up by the cluster admin are safe to use.
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    # Require the container to run without root privileges.
    rule: 'MustRunAsNonRoot'
  seLinux:
    # This policy assumes the nodes are using AppArmor rather than SELinux.
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName:  'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName:  'runtime/default'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 0
        max: 65535

```