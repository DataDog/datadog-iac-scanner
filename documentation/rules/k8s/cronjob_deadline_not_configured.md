---
title: "CronJob deadline not configured"
group_id: "Kubernetes / Kubernetes"
meta:
  name: "k8s/cronjob_deadline_not_configured"
  id: "192fe40b-b1c3-448a-aba2-6cc19a300fe3"
  display_name: "CronJob deadline not configured"
  cloud_provider: "Kubernetes"
  platform: "Kubernetes"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `192fe40b-b1c3-448a-aba2-6cc19a300fe3`

**Cloud Provider:** Kubernetes

**Platform:** Kubernetes

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)

### Description

 CronJobs must have a configured deadline. The `startingDeadlineSeconds` attribute must be defined. This attribute specifies the time window, in seconds relative to the scheduled start time, within which a missed job may still be started. Omitting `spec.startingDeadlineSeconds` leaves the CronJob without a configured deadline for missed starts, which can result in delayed or unpredictable job executions; define `spec.startingDeadlineSeconds` with an appropriate value to ensure predictable scheduling.


## Compliant Code Examples
```yaml
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "*/1 * * * *"
  startingDeadlineSeconds: 100
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox
            args:
            - /bin/sh
            - -c
            - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure

```
## Non-Compliant Code Examples
```yaml
#this is a problematic code where the query should report a result(s)
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
          - name: hello
            image: busybox
            args:
            - /bin/sh
            - -c
            - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure
```