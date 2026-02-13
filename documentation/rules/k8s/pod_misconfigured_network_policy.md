---
title: "Pod misconfigured network policy"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/pod_misconfigured_network_policy"
  id: "0401f71b-9c1e-4821-ab15-a955caa621be"
  display_name: "Pod misconfigured network policy"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `0401f71b-9c1e-4821-ab15-a955caa621be`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

### Description

 Each Pod should be targeted by a NetworkPolicy that includes both ingress and egress rules.
For Pods in the same namespace, a matching NetworkPolicy is determined by namespace. For Pods in a different namespace, the NetworkPolicy must explicitly select the Pod via `spec.podSelector.matchLabels`.
A NetworkPolicy satisfies ingress or egress if it lists the respective type in `spec.policyTypes`. When `spec.policyTypes` is omitted, ingress is treated as present, while egress is considered present only if `spec.egress` is non-empty.


## Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: negative1-pod
  namespace: negative1
spec:
  securityContext:
    runAsUser: 1000
  containers:
  - name: app
    image: images.my-company.example/app:v4
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: negative1-policy
  namespace: negative1
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: negative2-pod
  namespace: negative2-namespace
  labels:
    app: negative2-app
spec:
  securityContext:
    runAsUser: 1000
  containers:
  - name: app
    image: images.my-company.example/app:v4
    securityContext:
      allowPrivilegeEscalation: false
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: negative2-policy
  namespace: negative2-othernamespace
spec:
  podSelector:
    matchLabels:
      app: negative2-app
  policyTypes:
  - Ingress
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: negative3-pod
  namespace: negative3
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: negative3-netpol
  labels:
    policy: just-egress
  namespace: negative3
spec:
  podSelector: {}
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
    ports:
    - protocol: TCP
      port: 5978

```
## Non-Compliant Code Examples
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: positive2-pod
  namespace: positive2
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: positive2-netpol
  namespace: positive2
spec:
  podSelector: {}
  policyTypes: []

```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: positive1-pod
  namespace: positive1-one
  labels:
    app: shouldmatch
spec:
  containers:
  - name: nginx
    image: nginx:1.14.2
    ports:
    - containerPort: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: positive1-netpol
  labels:
    policy: no-ingress-no-egress
  namespace: positive1-anotherone
spec:
  podSelector:
    matchLabels:
      app: shouldmatch
  policyTypes: []

```