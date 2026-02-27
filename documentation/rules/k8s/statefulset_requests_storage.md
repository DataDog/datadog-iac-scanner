---
title: "StatefulSet requests storage"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/statefulset_requests_storage"
  id: "8cf4671a-cf3d-46fc-8389-21e7405063a2"
  display_name: "StatefulSet requests storage"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Build Process"
---
## Metadata

**Id:** `8cf4671a-cf3d-46fc-8389-21e7405063a2`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)

### Description

StatefulSets should not define a storage request under `spec.volumeClaimTemplates[*].spec.resources.requests.storage`. This rule flags any StatefulSet that includes this field.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web2
spec:
  serviceName: "nginx"
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: k8s.gcr.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  serviceName: "nginx"
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: k8s.gcr.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 1Gi
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web2
spec:
  serviceName: "nginx"
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: k8s.gcr.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 1Gi
  - metadata:
      name: www2
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 2Gi
```