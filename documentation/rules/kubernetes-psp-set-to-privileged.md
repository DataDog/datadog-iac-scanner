---
title: "PSP set to privileged"
group_id: "Kubernetes"
meta:
  name: "psp_set_to_privileged"
  id: "kubernetes-psp-set-to-privileged"
  display_name: "PSP set to privileged"
  cloud_provider: ""
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-psp-set-to-privileged{{< /copyable-code >}}

**Platform:** Kubernetes

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod_security_policy#privileged)

### Description

Pods should not be allowed to run with privileged execution. The PodSecurityPolicy resource's `spec.privileged` field should be set to false to prevent containers from gaining elevated host privileges. Allowing privileged containers grants broad host-level access and increases the risk of privilege escalation or host compromise.

## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: false
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'

```
## Non-Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: true 
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'

```