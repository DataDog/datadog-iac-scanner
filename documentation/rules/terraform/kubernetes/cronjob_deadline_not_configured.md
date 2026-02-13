---
title: "CronJob deadline not configured"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/cronjob_deadline_not_configured"
  id: "58876b44-a690-4e9f-9214-7735fa0dd15d"
  display_name: "CronJob deadline not configured"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Resource Management"
---
## Metadata

**Id:** `58876b44-a690-4e9f-9214-7735fa0dd15d`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Resource Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/cron_job#starting_deadline_seconds)

### Description

 CronJobs must include a configured deadline. The `starting_deadline_seconds` attribute in the resource spec (`kubernetes_cron_job[].spec.starting_deadline_seconds`) must be defined. This ensures missed job executions have a bounded retry window and are not indefinitely retried.


## Compliant Code Examples
```terraform
resource "kubernetes_cron_job" "demo2" {
  metadata {
    name = "demo"
  }
  spec {
    concurrency_policy            = "Replace"
    failed_jobs_history_limit     = 5
    schedule                      = "1 0 * * *"
    starting_deadline_seconds     = 10
    successful_jobs_history_limit = 10
    job_template {
      metadata {}
      spec {
        backoff_limit              = 2
        ttl_seconds_after_finished = 10
        template {
          metadata {}
          spec {
            container {
              name    = "hello"
              image   = "busybox"
              command = ["/bin/sh", "-c", "date; echo Hello from the Kubernetes cluster"]
            }
          }
        }
      }
    }
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_cron_job" "demo" {
  metadata {
    name = "demo"
  }
  spec {
    concurrency_policy            = "Replace"
    failed_jobs_history_limit     = 5
    schedule                      = "1 0 * * *"
    successful_jobs_history_limit = 10
    job_template {
      metadata {}
      spec {
        backoff_limit              = 2
        ttl_seconds_after_finished = 10
        template {
          metadata {}
          spec {
            container {
              name    = "hello"
              image   = "busybox"
              command = ["/bin/sh", "-c", "date; echo Hello from the Kubernetes cluster"]
            }
          }
        }
      }
    }
  }
}

```