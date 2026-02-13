---
title: "Object is using a deprecated API version"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/object_is_using_a_deprecated_api_version"
  id: "94b76ea5-e074-4ca2-8a03-c5a606e30645"
  display_name: "Object is using a deprecated API version"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `94b76ea5-e074-4ca2-8a03-c5a606e30645`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/reference/using-api/deprecation-guide/)

### Description

 Kubernetes APIs evolve over time and may be removed in newer releases. To prevent incompatibilities when upgrading Kubernetes, deprecated APIs should be replaced with newer, stable API versions. This rule checks a resource's apiVersion and kind against a mapping of deprecated apiVersions to their recommended replacements and flags resources that use deprecated APIs. The rule reports the expected API version for the resource kind and the actual (deprecated) apiVersion found, so maintainers can update manifests accordingly.


## Compliant Code Examples
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
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
---
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
            - name: optmount
              mountPath: /opt
      terminationGracePeriodSeconds: 30
      volumes:
        - name: optmount
          hostPath:
            path: /opt

```
## Non-Compliant Code Examples
```yaml
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: nginx-deployment
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
---
apiVersion: apps/v1beta2
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
            - name: optmount
              mountPath: /opt
      terminationGracePeriodSeconds: 30
      volumes:
        - name: optmount
          hostPath:
            path: /opt
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: minimal-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        pathType: Prefix
        backend:
          service:
            name: test
            port:
              number: 80
---
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: minimal-ingress1
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - http:
      paths:
      - path: /testpath
        pathType: Prefix
        backend:
          service:
            name: test
            port:
              number: 80
---
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox
            imagePullPolicy: IfNotPresent
            command:
            - /bin/sh
            - -c
            - date; echo Hello from kics
          restartPolicy: OnFailure

```