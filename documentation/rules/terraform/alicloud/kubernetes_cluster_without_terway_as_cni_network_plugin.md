---
title: "Kubernetes cluster without Terway as CNI network plugin"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/kubernetes_cluster_without_terway_as_cni_network_plugin"
  id: "b9b7ada8-3868-4a35-854e-6100a2bb863d"
  display_name: "Kubernetes cluster without Terway as CNI network plugin"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `b9b7ada8-3868-4a35-854e-6100a2bb863d`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/cs_kubernetes#cluster_network_type)

### Description

 Kubernetes clusters (`alicloud_cs_kubernetes`) must include the Terway CNI network plugin and define `pod_vswitch_ids`. Specifically, the `addons` block must include an entry for `terway-eniip`, and the `pod_vswitch_ids` attribute must be defined and not null. Terway enables ENI-based networking required for advanced network policies and proper pod communication. This rule flags `alicloud_cs_kubernetes` resources missing either the required `addons` entry or the `pod_vswitch_ids` attribute.


## Compliant Code Examples
```terraform
terraform {
  required_providers {
    alicloud = {
      source = "aliyun/alicloud"
      version = "1.160.0"
    }
  }
}

provider "alicloud" {
  access_key = "xxxxxx"
  secret_key = "xxxxxx"
}

resource "alicloud_cs_kubernetes" "k8s" {
  worker_number = 4
  worker_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]
  worker_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]

  addons {
    config = ""
    name   = "terway-eniip"
  }

  pod_vswitch_ids = ["id1"]
}

```
## Non-Compliant Code Examples
```terraform
terraform {
  required_providers {
    alicloud = {
      source = "aliyun/alicloud"
      version = "1.160.0"
    }
  }
}

provider "alicloud" {
  access_key = "xxxxxx"
  secret_key = "xxxxxx"
}

resource "alicloud_cs_kubernetes" "positive2" {
  worker_number = 4
  worker_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]
  worker_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]

  addons {
    config = ""
    name   = "terway-eniip"
  }
}

```

```terraform
terraform {
  required_providers {
    alicloud = {
      source = "aliyun/alicloud"
      version = "1.160.0"
    }
  }
}

provider "alicloud" {
  access_key = "xxxxxx"
  secret_key = "xxxxxx"
}

resource "alicloud_cs_kubernetes" "positive3" {
  worker_number = 4
  worker_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]
  worker_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]

  pod_vswitch_ids = ["id1"]
}

```

```terraform
terraform {
  required_providers {
    alicloud = {
      source = "aliyun/alicloud"
      version = "1.160.0"
    }
  }
}

provider "alicloud" {
  access_key = "xxxxxx"
  secret_key = "xxxxxx"
}

resource "alicloud_cs_kubernetes" "positive1" {
  worker_number = 4
  worker_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_vswitch_ids = ["vsw-id1", "vsw-id1", "vsw-id3"]
  master_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]
  worker_instance_types  = ["ecs.n4.small", "ecs.sn1ne.xlarge", "ecs.n4.xlarge"]
}

```