---
title: "Volume mount with OS directory write permissions"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/volume_mount_with_os_directory_write_permissions"
  id: "b7652612-de4e-4466-a0bf-1cd81f0c6063"
  display_name: "Volume mount with OS directory write permissions"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "HIGH"
  category: "Resource Management"
---
## Metadata

**Id:** `b7652612-de4e-4466-a0bf-1cd81f0c6063`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** High

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/storage/volumes/)

### Description

 Containers can mount sensitive directories from the host, granting potentially dangerous access to critical host configurations and binaries.
This rule flags container volume mounts where the mountPath is a host-sensitive directory (for example `/bin`, `/etc`, `/proc`, or `/`) and the `readOnly` attribute is missing or set to false.
Such mounts are expected to be set to read-only to avoid modification of host files and reduce the risk of privilege escalation or system compromise.


## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-0
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: pod-0
    volumeMounts:
    - mountPath: /bin
      name: vol-0
      readOnly: true
  volumes:
  - name: vol-0
    scaleIO:
      gateway: https://localhost:443/api
      system: scaleio
      protectionDomain: sd0
      storagePool: sp1
      volumeName: vol-0
      secretRef:
        name: sio-secret
      fsType: xfs

---
apiVersion: v1
kind: Pod
metadata:
  name: pod-1
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: pod-0
    volumeMounts:
    - mountPath: /project-mount
      name: vol-0
  volumes:
  - name: vol-0
    scaleIO:
      gateway: https://localhost:443/api
      system: scaleio
      protectionDomain: sd0
      storagePool: sp1
      volumeName: vol-0
      secretRef:
        name: sio-secret
      fsType: xfs

---
apiVersion: v1
kind: Pod
metadata:
  name: pod-2
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: pod-0
    volumeMounts:
    - mountPath: /var/run
      name: vol-0
      readOnly: true
  volumes:
  - name: vol-0
    scaleIO:
      gateway: https://localhost:443/api
      system: scaleio
      protectionDomain: sd0
      storagePool: sp1
      volumeName: vol-0
      secretRef:
        name: sio-secret
      fsType: xfs

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-0
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: pod-0
    volumeMounts:
    - mountPath: /bin
      name: vol-0
    - mountPath: /var/run
      name: vol-1
      readOnly: false
  volumes:
  - name: vol-0
    scaleIO:
      gateway: https://localhost:443/api
      system: scaleio
      protectionDomain: sd0
      storagePool: sp1
      volumeName: vol-0
      secretRef:
        name: sio-secret
      fsType: xfs
---
apiVersion: v1
kind: Pod
metadata:
  name: pod-1
spec:
  containers:
  - image: k8s.gcr.io/test-webserver
    name: pod-1
    volumeMounts:
    - mountPath: /var/run
      name: vol-0
    - mountPath: /bin
      name: vol-1
      readOnly: false
  volumes:
  - name: vol-0
    scaleIO:
      gateway: https://localhost:443/api
      system: scaleio
      protectionDomain: sd0
      storagePool: sp1
      volumeName: vol-0
      secretRef:
        name: sio-secret
      fsType: xfs

```