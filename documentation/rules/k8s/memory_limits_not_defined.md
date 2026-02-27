---
title: "Memory limits not defined"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/memory_limits_not_defined"
  id: "b14d1bc4-a208-45db-92f0-e21f8e2588e9"
  display_name: "Memory limits not defined"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `b14d1bc4-a208-45db-92f0-e21f8e2588e9`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/)

### Description

Memory limits (`resources.limits.memory`) should be defined for each container (including `initContainers`) to prevent resource exhaustion by ensuring containers cannot consume more memory than allotted. Defining memory limits helps maintain cluster stability and predictable resource scheduling.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo-negative
  namespace: mem-example
spec:
  containers:
  - name: memory-demo-ctr
    image: polinux/stress
    resources:
      limits:
        memory: "200Mi"
      requests:
        memory: "100Mi"
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]

```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment-neg
  labels:
    app: test-neg
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test-neg
  template:
    metadata:
      labels:
        app: test-neg
    spec:
      containers:
        - name:  pause
          image: k8s.gcr.io/pause
          resources:
            limits:
              cpu: 0.5
              memory: 512Mi
            requests:
              cpu: 0.5
              memory: 512Mi

```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
  labels:
    app: test
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
        - name:  pause
          image: k8s.gcr.io/pause
          resources:
            limits:
              cpu: 1
            requests:
              cpu: 0.5
              memory: 512Mi

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo-1
  namespace: mem-example
spec:
  containers:
  - name: memory-demo-ctr
    image: polinux/stress
    resources:
      requests:
        cpu: "0.5"
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]
---
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo-2
  namespace: mem-example
spec:
  containers:
  - name: memory-demo-ctr
    image: polinux/stress
    resources:
      requests:
        cpu: "0.5"
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]
---
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo-3
  namespace: mem-example
spec:
  containers:
  - name: memory-demo-ctr
    image: polinux/stress
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]
---
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo-4
  namespace: mem-example
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
    - name: sec-ctx-vol
      emptyDir: { }
  containers:
  - name: memory-demo-ctr
    image: polinux/stress
    command: ["stress"]

```