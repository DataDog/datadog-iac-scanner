---
title: "Docker daemon socket is exposed to containers"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/docker_daemon_socket_is_exposed_to_containers"
  id: "a6f34658-fdfb-4154-9536-56d516f65828"
  display_name: "Docker daemon socket is exposed to containers"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Access Control"
---
## Metadata

**Id:** `a6f34658-fdfb-4154-9536-56d516f65828`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Access Control

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/storage/volumes/)

### Description

The Docker daemon socket should not be exposed to containers. Mounting /var/run/docker.sock into a container grants the container direct access to the host Docker daemon, which can enable privilege escalation and full control of the host. Alternatives include using isolated build environments, container runtime APIs with proper access controls, or dedicated build services.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: test-container
    volumeMounts:
    - mountPath: /test-pd
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:
      path: /data
      type: Directory
```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: test-container
    volumeMounts:
    - mountPath: /test-pd
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:
      path: /var/run/docker.sock
      type: Directory

---

apiVersion: v1
kind: ReplicationController
metadata:
  name: node-manager
  labels:
    name: node-manager
spec:
    selector:
      name: node-manager
    template:
      metadata:
        labels:
          name: node-manager
      spec:
          containers:
          - image: k8s.gcr.io/test-webserver
            name: test-container
            volumeMounts:
            - mountPath: /test-pd
              name: test-volume
          volumes:
          - name: test-volume
            hostPath:
              path: /var/run/docker.sock
              type: Directory

---

apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "*/1 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - image: k8s.gcr.io/test-webserver
            name: test-container
            volumeMounts:
            - mountPath: /test-pd
              name: test-volume
          volumes:
          - name: test-volume
            hostPath:
              path: /var/run/docker.sock
              type: Directory
```