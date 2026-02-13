---
title: "Using default namespace"
group_id: "Terraform / Kubernetes"
meta:
  name: "kubernetes/using_default_namespace"
  id: "abcb818b-5af7-4d72-aba9-6dd84956b451"
  display_name: "Using default namespace"
  cloud_provider: "Kubernetes"
  platform: "Terraform"
  severity: "LOW"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `abcb818b-5af7-4d72-aba9-6dd84956b451`

**Cloud Provider:** Kubernetes

**Platform:** Terraform

**Severity:** Low

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/pod#namespace)

### Description

 Resources must not use the `default` namespace.
This rule flags Kubernetes resources that either lack `metadata` or `metadata.namespace`, or have `metadata.namespace` set to `default`.
It applies to resource kinds: `kubernetes_ingress`, `kubernetes_config_map`, `kubernetes_secret`, `kubernetes_service`, `kubernetes_cron_job`, `kubernetes_service_account`, `kubernetes_role`, `kubernetes_role_binding`, `kubernetes_pod`, `kubernetes_deployment`, `kubernetes_daemonset`, `kubernetes_job`, `kubernetes_stateful_set`, `kubernetes_replication_controller`.


## Compliant Code Examples
```terraform
resource "kubernetes_pod" "test3" {
  metadata {
    name = "terraform-example"
    namespace = "terraform-namespace"
  }
}

resource "kubernetes_cron_job" "test4" {
  metadata {
    name = "terraform-example"
    namespace = "terraform-namespace"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "kubernetes_pod" "test" {
  metadata {
    name = "terraform-example"
    namespace = "default"
  }
}

resource "kubernetes_cron_job" "test2" {
  metadata {
    name = "terraform-example"
  }
}

```