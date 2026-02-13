---
title: "Memory requests not defined"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/memory_requests_not_defined"
  id: "229588ef-8fde-40c8-8756-f4f2b5825ded"
  display_name: "Memory requests not defined"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `229588ef-8fde-40c8-8756-f4f2b5825ded`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/configure-pod-container/assign-memory-resource/)

### Description

 Memory requests should be defined for each container so the scheduler and kubelet can account for and reserve the requested memory and help prevent over-provisioning on nodes. Without a defined memory request, the scheduler may overcommit node memory, increasing the risk of resource contention and out-of-memory (OOM) terminations.


## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo
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
  name: test-deployment-ctr-neg
  labels:
    app: test-neg
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test-ctr-neg
  template:
    metadata:
      labels:
        app: test-ctr-neg
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
  name: test-deployment2
  labels:
    app: test2
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test2
  template:
    metadata:
      labels:
        app: test2
    spec:
      containers:
        - name:  pause
          image: k8s.gcr.io/pause
          resources:
            limits:
              cpu: 0.5
              memory: 512Mi

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo
  namespace: mem-example
spec:
  containers:
  - name: memory-demo-ctr-1
    image: polinux/stress
    resources:
      limits:
        memory: "200Mi"
      requests:
        cpu: "0.5"
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]
---
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo-1
  namespace: mem-example
spec:
  containers:
  - name: memory-demo-ctr-2
    image: polinux/stress
    resources:
      limits:
        memory: "200Mi"
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
  - name: memory-demo-ctr-3
    image: polinux/stress
    command: ["stress"]
    args: ["--vm", "1", "--vm-bytes", "150M", "--vm-hang", "1"]
---
apiVersion: v1
kind: Pod
metadata:
  name: memory-demo-3
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
  - name: memory-demo-ctr-4
    image: polinux/stress
    command: ["stress"]

```