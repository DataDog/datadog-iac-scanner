---
title: "CS Kubernetes node pool auto repair disabled"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/cs_kubernetes_node_pool_auto_repair_disabled"
  id: "81ce9394-013d-4731-8fcc-9d229b474073"
  display_name: "CS Kubernetes node pool auto repair disabled"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `81ce9394-013d-4731-8fcc-9d229b474073`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/cs_kubernetes_node_pool#auto_repair)

### Description

 Verifies that Alicloud Container Service node pools (`alicloud_cs_kubernetes_node_pool`) have `management.auto_repair` set to `true`. The `auto_repair` setting periodically detects and repairs failing nodes to maintain a healthy, running cluster. The rule reports when the `management` block is missing, when `auto_repair` is not present, or when `auto_repair` is explicitly set to `false`. Remediation is to add a `management` block with `auto_repair = true`, or to update the existing `auto_repair` value to `true`.


## Compliant Code Examples
```terraform
resource "alicloud_cs_kubernetes_node_pool" "default1" {
  name                 = var.name
  cluster_id           = alicloud_cs_managed_kubernetes.default.0.id
  vswitch_ids          = [alicloud_vswitch.default.id]
  instance_types       = [data.alicloud_instance_types.default.instance_types.0.id]
  system_disk_category = "cloud_efficiency"
  system_disk_size     = 40

  # only key_name is supported in the management node pool
  key_name = alicloud_key_pair.default.key_name

  # you need to specify the number of nodes in the node pool, which can be zero
  desired_size = 1

  # management node pool configuration.
  management {
    auto_repair     = true
    auto_upgrade    = true
    surge           = 1
    max_unavailable = 1
  }

}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_cs_kubernetes_node_pool" "default3" {
  name                 = var.name
  cluster_id           = alicloud_cs_managed_kubernetes.default.0.id
  vswitch_ids          = [alicloud_vswitch.default.id]
  instance_types       = [data.alicloud_instance_types.default.instance_types.0.id]
  system_disk_category = "cloud_efficiency"
  system_disk_size     = 40

  # only key_name is supported in the management node pool
  key_name = alicloud_key_pair.default.key_name

  # you need to specify the number of nodes in the node pool, which can be zero
  desired_size = 1

  # management node pool configuration.
  management {
    auto_repair     = false
    auto_upgrade    = true
    surge           = 1
    max_unavailable = 1
  }
}

```

```terraform
resource "alicloud_cs_kubernetes_node_pool" "default4" {
  name                 = var.name
  cluster_id           = alicloud_cs_managed_kubernetes.default.0.id
  vswitch_ids          = [alicloud_vswitch.default.id]
  instance_types       = [data.alicloud_instance_types.default.instance_types.0.id]
  system_disk_category = "cloud_efficiency"
  system_disk_size     = 40

  # only key_name is supported in the management node pool
  key_name = alicloud_key_pair.default.key_name

  # you need to specify the number of nodes in the node pool, which can be zero
  desired_size = 1

  # management node pool configuration.
  management {
    auto_upgrade    = true
    surge           = 1
    max_unavailable = 1
  }
}

```

```terraform
resource "alicloud_cs_kubernetes_node_pool" "default2" {
  name           = var.name
  cluster_id     = alicloud_cs_managed_kubernetes.default.0.id
  vswitch_ids    = [alicloud_vswitch.default.id]
  instance_types = [data.alicloud_instance_types.default.instance_types.0.id]

  system_disk_category = "cloud_efficiency"
  system_disk_size     = 40
  key_name             = alicloud_key_pair.default.key_name

  # comment out node_count and specify a new field desired_size
  # node_count = 1

  desired_size = 1
}

```