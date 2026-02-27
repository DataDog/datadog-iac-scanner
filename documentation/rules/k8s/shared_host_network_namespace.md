---
title: "Shared host network namespace"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/shared_host_network_namespace"
  id: "6b6bdfb3-c3ae-44cb-88e4-7405c1ba2c8a"
  display_name: "Shared host network namespace"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Resource Management"
---
## Metadata

**Id:** `6b6bdfb3-c3ae-44cb-88e4-7405c1ba2c8a`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

### Description

Containers should not share the host network namespace. Setting `spec.hostNetwork` to true causes a pod's containers to use the node's network namespace, exposing host network interfaces and reducing network isolation. This rule flags resources where `spec.hostNetwork` is true; it expects `spec.hostNetwork` to be false or undefined.

## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
    - name: sec-ctx-vol
      emptyDir: { }
  containers:
    - name: sec-ctx-demo
      image: busybox
      command: [ "sh", "-c", "sleep 1h" ]
      volumeMounts:
        - name: sec-ctx-vol
          mountPath: /data/demo
      securityContext:
        allowPrivilegeEscalation: false
```

```yaml
apiVersion: serving.knative.dev/v1
kind: Configuration
metadata:
  name: dummy-config
  namespace: knative-sequence
spec:
  template:
    spec:
      hostNetwork: false
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
      volumes:
        - name: sec-ctx-vol
          emptyDir: { }
      containers:
        - name: sec-ctx-demo
          image: busybox
          command: [ "sh", "-c", "sleep 1h" ]
          volumeMounts:
            - name: sec-ctx-vol
              mountPath: /data/demo
          securityContext:
            allowPrivilegeEscalation: false

```
## Non-Compliant Code Examples
```yaml
apiVersion: serving.knative.dev/v1
kind: Configuration
metadata:
  name: dummy-config
  namespace: knative-sequence
spec:
  template:
    spec:
      hostNetwork: true
      securityContext:
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
      volumes:
        - name: sec-ctx-vol
          emptyDir: { }
      containers:
        - name: sec-ctx-demo
          image: busybox
          command: [ "sh", "-c", "sleep 1h" ]
          volumeMounts:
            - name: sec-ctx-vol
              mountPath: /data/demo
          securityContext:
            allowPrivilegeEscalation: false

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  hostNetwork: true
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
    - name: sec-ctx-vol
      emptyDir: { }
  containers:
    - name: sec-ctx-demo
      image: busybox
      command: [ "sh", "-c", "sleep 1h" ]
      volumeMounts:
        - name: sec-ctx-vol
          mountPath: /data/demo
      securityContext:
        allowPrivilegeEscalation: false
```