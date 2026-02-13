---
title: "StatefulSet without PodDisruptionBudget"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/statefulset_without_pod_disruption_budget"
  id: "1db3a5a5-bf75-44e5-9e44-c56cfc8b1ac5"
  display_name: "StatefulSet without PodDisruptionBudget"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Availability"
---
## Metadata

**Id:** `1db3a5a5-bf75-44e5-9e44-c56cfc8b1ac5`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Availability

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/tasks/run-application/configure-pdb/)

### Description

 StatefulSets with more than one replica should have a PodDisruptionBudget that targets the StatefulSet's pod selector (`spec.selector.matchLabels`) to ensure high availability.  
This prevents simultaneous voluntary evictions from reducing the number of available replicas and helps maintain service continuity.  
The rule flags StatefulSets where no PodDisruptionBudget matches the StatefulSet's selector.


## Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata:
  name: nginx-pdb
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app: nginx33
      run: test
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: nginx123
      run: test
  serviceName: "nginx"
  replicas: 3
  template:
    metadata:
      labels:
        app: nginx
    spec:
      terminationGracePeriodSeconds: 10
      containers:
      - name: nginx
        image: k8s.gcr.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html

```
## Non-Compliant Code Examples
```yaml
apiVersion: policy/v1beta1
kind: PodDisruptionBudget
metadata:
  name: nginx-pdb
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app: xpto
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  requiredDropCapabilities:
    - ALL
  selector:
    matchLabels:
      app: nginx
  serviceName: "nginx"
  replicas: 3
  template:
    metadata:
      labels:
        app: nginx
    spec:
      terminationGracePeriodSeconds: 10
      containers:
      - name: nginx
        image: k8s.gcr.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html

```