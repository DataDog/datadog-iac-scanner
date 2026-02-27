---
title: "Root containers admitted"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/root_containers_admitted"
  id: "4c415497-7410-4559-90e8-f2c8ac64ee38"
  display_name: "Root containers admitted"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Best Practices"
---
## Metadata

**Id:** `4c415497-7410-4559-90e8-f2c8ac64ee38`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Medium

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod_security_policy#run_as_user)

### Description

Containers must not run with root privileges. The PodSecurityPolicy must set `privileged` and `allow_privilege_escalation` to `false`, and `spec.run_as_user.rule` must be `MustRunAsNonRoot`. The group settings `fs_group` and `supplemental_groups` must use `MustRunAs` and their `range.min` must not allow `0` (root).  

Noncompliant policies permit privilege escalation or root user/group IDs, increasing the risk of container breakout and unauthorized host access; this rule identifies PSPs that do not enforce these restrictions.

## Compliant Code Examples
```terraform
resource "kubernetes_pod_security_policy" "example2" {
  metadata {
    name = "terraform-example"
  }
  spec {
    privileged                 = false
    allow_privilege_escalation = false

    volumes = [
      "configMap",
      "emptyDir",
      "projected",
      "secret",
      "downwardAPI",
      "persistentVolumeClaim",
    ]

    run_as_user {
      rule = "MustRunAsNonRoot"
    }

    se_linux {
      rule = "RunAsAny"
    }

    supplemental_groups {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    fs_group {
      rule = "MustRunAs"
      range {
        min = 1
        max = 65535
      }
    }

    read_only_root_filesystem = true
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_pod_security_policy" "example" {
  metadata {
    name = "terraform-example"
  }
  spec {
    privileged                 = true
    allow_privilege_escalation = true

    volumes = [
      "configMap",
      "emptyDir",
      "projected",
      "secret",
      "downwardAPI",
      "persistentVolumeClaim",
    ]

    run_as_user {
      rule = "RunAsAny"
    }

    se_linux {
      rule = "RunAsAny"
    }

    supplemental_groups {
      rule = "RunAsAny"
      range {
        min = 1
        max = 65535
      }
    }

    fs_group {
      rule = "MustRunAs"
      range {
        min = 0
        max = 65535
      }
    }
  }
}

```