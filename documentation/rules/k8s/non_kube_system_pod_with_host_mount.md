---
title: "Non kube-system pod with host mount"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/non_kube_system_pod_with_host_mount"
  id: "aa8f7a35-9923-4cad-bd61-a19b7f6aac91"
  display_name: "Non kube-system pod with host mount"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Access Control"
---
## Metadata

**Id:** `aa8f7a35-9923-4cad-bd61-a19b7f6aac91`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/storage/volumes/)

### Description

 Non `kube-system` workloads should not include a `hostPath` volume mount. The rule detects `hostPath.path` in pod specs (including pod template specs) and in `PersistentVolume` resources and reports an issue when present. If `metadata.namespace` is not set, the resource is treated as being in the `default` namespace.


## Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd-elasticsearch
  namespace: kube-system
  labels:
    k8s-app: fluentd-logging
spec:
  selector:
    matchLabels:
      name: fluentd-elasticsearch
  template:
    metadata:
      labels:
        name: fluentd-elasticsearch
    spec:
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      containers:
        - name: fluentd-elasticsearch
          image: quay.io/fluentd_elasticsearch/fluentd:v2.5.2
          resources:
            limits:
              cpu: 500m
              memory: 200Mi
            requests:
              cpu: 100m
              memory: 200Mi
          volumeMounts:
            - name: varlog
              mountPath: /var/log
            - name: varlibdockercontainers
              mountPath: /var/lib/docker/containers
              readOnly: true
      terminationGracePeriodSeconds: 30
      volumes:
        - name: varlog
          hostPath:
            path: /var/log
        - name: varlibdockercontainers
          hostPath:
            path: /var/lib/docker/containers
---
apiVersion: v1
kind: Pod
metadata:
  name: redis
  namespace: kube-system
spec:
  containers:
    - name: redis
      image: redis
      volumeMounts:
        - name: redis-storage
          mountPath: /data/redis
  volumes:
    - name: redis-storage
      hostPath:
        path: /var/redis/data
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: kube-system
  labels:
    app: nginx
spec:
  replicas: 3
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
          image: nginx:1.14.2
          ports:
            - containerPort: 80
          volumeMounts:
            - name: static-page-dir
              mountPath: /var/www/app/static
      volumes:
        - name: static-page-dir
          hostPath:
            path: /var/local/static
            type: DirectoryOrCreate
---
kind: PersistentVolume
apiVersion: v1
metadata:
  name: pv-001
  namespace: kube-system
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/sys"

```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd-elasticsearch
  namespace: logs
  labels:
    k8s-app: fluentd-logging
spec:
  selector:
    matchLabels:
      name: fluentd-elasticsearch
  template:
    metadata:
      labels:
        name: fluentd-elasticsearch
    spec:
      tolerations:
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      containers:
        - name: fluentd-elasticsearch
          image: quay.io/fluentd_elasticsearch/fluentd:v2.5.2
          resources:
            limits:
              cpu: 500m
              memory: 200Mi
            requests:
              cpu: 100m
              memory: 200Mi
          volumeMounts:
            - name: varlog
              mountPath: /var/log
            - name: varlibdockercontainers
              mountPath: /var/lib/docker/containers
              readOnly: true
      terminationGracePeriodSeconds: 30
      volumes:
        - name: varlog
          hostPath:
            path: /var/log
        - name: varlibdockercontainers
          hostPath:
            path: /var/lib/docker/containers
---
apiVersion: v1
kind: Pod
metadata:
  name: redis
spec:
  containers:
    - name: redis
      image: redis
      volumeMounts:
        - name: redis-storage
          mountPath: /data/redis
  volumes:
    - name: redis-storage
      hostPath:
        path: /var/redis/data
---
apiVersion: v1
kind: Pod
metadata:
  name: redis-memcache
  namespace: memcache
spec:
  containers:
    - name: redis
      image: redis
      volumeMounts:
        - name: redis-storage
          mountPath: /data/redis
  volumes:
    - name: redis-storage
      hostPath:
        path: /var/redis/data
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: default
  labels:
    app: nginx
spec:
  replicas: 3
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
          image: nginx:1.14.2
          ports:
            - containerPort: 80
          volumeMounts:
            - name: static-page-dir
              mountPath: /var/www/app/static
      volumes:
        - name: static-page-dir
          hostPath:
            path: /var/local/static
            type: DirectoryOrCreate
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment-undefined-ns
  labels:
    app: nginx
spec:
  replicas: 3
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
          image: nginx:1.14.2
          ports:
            - containerPort: 80
          volumeMounts:
            - name: static-page-dir
              mountPath: /var/www/app/static
      volumes:
        - name: static-page-dir
          hostPath:
            path: /var/local/static
            type: DirectoryOrCreate
---
kind: PersistentVolume
apiVersion: v1
metadata:
  name: pv-001
  namespace: default
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/"
---
kind: PersistentVolume
apiVersion: v1
metadata:
  name: pv-002
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/boot"
---
apiVersion: serving.knative.dev/v1
kind: Revision
metadata:
  name: dummy-rev
  namespace: knative-sequence
spec:
  containers:
    - name: redis
      image: redis
      volumeMounts:
        - name: redis-storage
          mountPath: /data/redis
  volumes:
    - name: redis-storage
      hostPath:
        path: /var/redis/data

```