---
title: "Cluster allows unsafe sysctls"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/cluster_allows_unsafe_sysctls"
  id: "9127f0d9-2310-42e7-866f-5fd9d20dcbad"
  display_name: "Cluster allows unsafe sysctls"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `9127f0d9-2310-42e7-866f-5fd9d20dcbad`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/)

### Description

A Kubernetes cluster must not allow unsafe sysctls. Allowing unsafe sysctls can let a Pod influence other Pods, harm node stability, or consume CPU or memory beyond resource limits.
`spec.securityContext.sysctls` must not include unsafe sysctls, and `allowedUnsafeSysctls` must be undefined. This rule detects PodSecurityPolicy resources where `allowedUnsafeSysctls` is defined and flags any `spec.securityContext.sysctls` entries that are not in the defined safe list.
Only a limited set of sysctls are considered safe; all others are treated as unsafe and should not be used.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-example
spec:
  securityContext:
    sysctls:
    - name: kernel.shm_rmid_forced
      value: "0"
    - name: net.ipv4.ip_local_port_range
      value: "0"
  containers:
    - name: test1
      image: nginx
---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: sysctl-psp
spec:
  forbiddenSysctls:
  - kernel.shm_rmid_forced
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny

```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app-neg
  labels:
    app: test-app-neg
spec:
  selector:
    matchLabels:
      app: test-app-neg
  template:
    metadata:
      labels:
        app: test-app-neg
    spec:
      securityContext:
        sysctls:
        - name: kernel.shm_rmid_forced
          value: "0"
        - name: net/ipv4/tcp_syncookies
          value: "1"
      containers:
      - name: test-ubuntu
        image: ubuntu

```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
  labels:
    app: test-app
spec:
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      securityContext:
        sysctls:
        - name: kernel.sem
          value: "128 32768 128 4096"
      containers:
      - name: test-ubuntu
        image: ubuntu

```

```yaml
#this is a problematic code where the query should report a result(s)
apiVersion: v1
kind: Pod
metadata:
  name: sysctl-example
spec:
  securityContext:
    sysctls:
    - name: kernel.shm_rmid_forced
      value: "0"
    - name: net.core.somaxconn
      value: "1024"
    - name: kernel.msgmax
      value: "65536"
  containers:
    - name: test1
      image: nginx
---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: sysctl-psp
spec:
  allowedUnsafeSysctls:
  - kernel.msg*
  forbiddenSysctls:
  - kernel.shm_rmid_forced
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny

```