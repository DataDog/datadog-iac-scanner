---
title: "Incorrect volume claim access mode ReadWriteOnce"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/incorrect_volume_claim_access_mode_read_write_once"
  id: "3878dc92-8e5d-47cf-9cdd-7590f71d21b9"
  display_name: "Incorrect volume claim access mode ReadWriteOnce"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Build Process"
---
## Metadata

**Id:** `3878dc92-8e5d-47cf-9cdd-7590f71d21b9`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Build Process

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/)

### Description

Kubernetes StatefulSets must include exactly one volume claim template with the access mode `ReadWriteOnce`. The rule flags StatefulSets that either do not include any `spec.volumeClaimTemplates` with `accessModes` containing `ReadWriteOnce` (issue type: MissingAttribute) or include more than one such template (issue type: IncorrectValue). The check inspects each entry in `spec.volumeClaimTemplates[].spec.accessModes` to determine the presence of `ReadWriteOnce`.

## Compliant Code Examples
```yaml
#this code is a correct code for which the query should not find any result
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: nginx # has to match .spec.template.metadata.labels
  serviceName: "nginx"
  replicas: 3 # by default is 1
  template:
    metadata:
      labels:
        app: nginx # has to match .spec.selector.matchLabels
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
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi
```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: nginx # has to match .spec.template.metadata.labels
  serviceName: "nginx"
  replicas: 3 # by default is 1
  template:
    metadata:
      labels:
        app: nginx # has to match .spec.selector.matchLabels
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
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi
  - metadata:
      name: aaa
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi

---

apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web2
spec:
  selector:
    matchLabels:
      app: nginx # has to match .spec.template.metadata.labels
  serviceName: "nginx"
  replicas: 3 # by default is 1
  template:
    metadata:
      labels:
        app: nginx # has to match .spec.selector.matchLabels
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
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWrite" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi
  - metadata:
      name: aaa
    spec:
      accessModes: [ "ReadWrite" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi
```