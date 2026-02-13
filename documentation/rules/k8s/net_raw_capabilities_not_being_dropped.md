---
title: "NET_RAW capabilities not dropped"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/net_raw_capabilities_not_being_dropped"
  id: "dbbc6705-d541-43b0-b166-dd4be8208b54"
  display_name: "NET_RAW capabilities not dropped"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `dbbc6705-d541-43b0-b166-dd4be8208b54`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

### Description

 Containers should drop `ALL` or at least `NET_RAW` capabilities.  
The container's `securityContext.capabilities.drop` field must include `ALL` or `NET_RAW`.  
If the `drop` list is undefined or does not include these capabilities, the policy reports a violation.


## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  containers:
      - name: payment
        image: nginx
        securityContext:
          capabilities:
            drop:
              - ALL
            add:
              - NET_BIND_SERVICE
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
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-unhealthy-deployment
  labels:
    app: redis
spec:
  replicas: 3
  selector:
    matchLabels:
      app: redis
  template:
    metadata:      
      labels:
        app: redis
    spec:
      hostNetwork: true
      hostPID: true 
      hostIPC: true
      containers:
      - name: redis
        image: redis:latest
        ports:
        - containerPort: 9001
          hostPort: 9001
        securityContext:
          privileged: true
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: true
          runAsUser: 0
          capabilities:
            add:
              - NET_ADMIN
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: example
spec:
  containers:
      - name: payment
        image: nginx
        securityContext:
          capabilities:
            drop:
              - SYS_ADMIN
      - name: payment2
        image: nginx
      - name: payment4
        image: nginx
        securityContext:
          capabilities:
            add:
              - NET_BIND_SERVICE
      - name: payment3
        image: nginx
        securityContext:
          allowPrivilegeEscalation: false

```