---
title: "Shared service account"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/shared_service_account"
  id: "kubernetes-shared-service-account"
  display_name: "Shared service account"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** {{< copyable-code >}}kubernetes-shared-service-account{{< /copyable-code >}}

**Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)

### Description

A service account token is shared between workloads. The rule detects multiple workload manifests that reference the same `serviceAccountName` in their spec. Sharing a service account increases the blast radius and can violate least-privilege principles by causing credentials and permissions to be shared across workloads.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  serviceAccountName : service1
  containers:
  - name: mycontainer
    image: redis
---
apiVersion: v1
kind: Pod
metadata:
  name: pod2
spec:
  serviceAccountName : service2
  containers:
  - name: envars-test-container
    image: nginx

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  serviceAccountName : service1
  containers:
  - name: mycontainer
    image: redis
---
apiVersion: v1
kind: Pod
metadata:
  name: pod2
spec:
  serviceAccountName : service1
  containers:
  - name: envars-test-container
    image: nginx

```