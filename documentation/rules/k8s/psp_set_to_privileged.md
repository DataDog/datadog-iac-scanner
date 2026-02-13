---
title: "PSP set to privileged"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/psp_set_to_privileged"
  id: "c48e57d3-d642-4e0b-90db-37f807b41b91"
  display_name: "PSP set to privileged"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `c48e57d3-d642-4e0b-90db-37f807b41b91`

**Cloud Provider:** Kubernetes

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