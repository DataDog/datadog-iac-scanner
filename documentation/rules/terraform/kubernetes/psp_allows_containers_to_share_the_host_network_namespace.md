---
title: "PSP allows containers to share the host network namespace"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/psp_allows_containers_to_share_the_host_network_namespace"
  id: "4950837c-0ce5-4e42-9bee-a25eae73740b"
  display_name: "PSP allows containers to share the host network namespace"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "HIGH"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `4950837c-0ce5-4e42-9bee-a25eae73740b`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** High

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod_security_policy#host_network)

### Description

Checks whether `kubernetes_pod_security_policy` resources allow containers to share the host network namespace. The rule identifies resources where `spec.hostNetwork` is set to `true`. Allowing `hostNetwork` exposes the node's network stack to pods, increasing attack surface and risking port collisions and privilege escalation. `spec.hostNetwork` should be set to `false` or left `undefined` to ensure pods use isolated network namespaces.

## Compliant Code Examples
```terraform
resource "kubernetes_pod_security_policy" "example" {
  metadata {
    name = "terraform-example"
  }
  spec {
    privileged                 = false
    allow_privilege_escalation = false
    host_network               = false

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
    privileged                 = false
    allow_privilege_escalation = false
    host_network               = true

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