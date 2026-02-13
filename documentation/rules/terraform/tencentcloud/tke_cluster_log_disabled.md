---
title: "Beta - TKE cluster log agent is not enabled"
group_id: "Terraform / TencentCloud"
meta:
  name: "tencentcloud/tke_cluster_log_disabled"
  id: "fe405074-7e18-40f9-9aef-024aa1d0a889"
  display_name: "Beta - TKE cluster log agent is not enabled"
  cloud_provider: "TencentCloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Observability"
---
## Metadata

**Id:** `fe405074-7e18-40f9-9aef-024aa1d0a889`

**Cloud Provider:** TencentCloud

**Platform:** Terraform

**Severity:** Low

**Category:** Observability

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs/resources/kubernetes_cluster#log_agent)

### Description

 TKE cluster `log_agent` must be present and `log_agent.enabled` must be set to `true`.
The rule flags resources of type `tencentcloud_kubernetes_cluster` when the `log_agent` attribute is missing or null, or when `log_agent.enabled` is `false`.


## Compliant Code Examples
```terraform
resource "tencentcloud_vpc" "vpc" {
  name       = "vpc"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_kubernetes_cluster" "managed_cluster" {
  vpc_id                  = tencentcloud_vpc.vpc.id
  cluster_max_pod_num     = 32
  cluster_name            = "test"
  cluster_desc            = "test cluster desc"
  cluster_max_service_num = 256
  cluster_internet        = true
  cluster_deploy_type     = "MANAGED_CLUSTER"
  network_type            = "VPC-CNI"
  eni_subnet_ids          = ["subnet-bk1etlyu"]
  service_cidr            = "10.1.0.0/24"

  worker_config {
    count                      = 1
    availability_zone          = "ap-guangzhou-7"
    instance_type              = "S2.LARGE16"
    system_disk_type           = "CLOUD_PREMIUM"
    system_disk_size           = 60
    internet_charge_type       = "TRAFFIC_POSTPAID_BY_HOUR"
    internet_max_bandwidth_out = 100
    public_ip_assigned         = true
    subnet_id                  = "subnet-t5dv27rs"

    data_disk {
      disk_type = "CLOUD_PREMIUM"
      disk_size = 50
    }

    enhanced_security_service = false
    enhanced_monitor_service  = false
  }

  log_agent {
    enabled = true
  }

  labels = {
    "test1" = "test1",
    "test2" = "test2",
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "tencentcloud_vpc" "vpc" {
  name       = "vpc"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_kubernetes_cluster" "managed_cluster" {
  vpc_id                  = tencentcloud_vpc.vpc.id
  cluster_max_pod_num     = 32
  cluster_name            = "test"
  cluster_desc            = "test cluster desc"
  cluster_max_service_num = 256
  cluster_internet        = true
  cluster_deploy_type     = "MANAGED_CLUSTER"
  network_type            = "VPC-CNI"
  eni_subnet_ids          = ["subnet-bk1etlyu"]
  service_cidr            = "10.1.0.0/24"

  worker_config {
    count                      = 1
    availability_zone          = "ap-guangzhou-7"
    instance_type              = "S2.LARGE16"
    system_disk_type           = "CLOUD_PREMIUM"
    system_disk_size           = 60
    internet_charge_type       = "TRAFFIC_POSTPAID_BY_HOUR"
    internet_max_bandwidth_out = 100
    public_ip_assigned         = true
    subnet_id                  = "subnet-t5dv27rs"

    data_disk {
      disk_type = "CLOUD_PREMIUM"
      disk_size = 50
    }

    enhanced_security_service = false
    enhanced_monitor_service  = false
  }

  labels = {
    "test1" = "test1",
    "test2" = "test2",
  }
}

```

```terraform
resource "tencentcloud_vpc" "vpc" {
  name       = "vpc"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_kubernetes_cluster" "managed_cluster" {
  vpc_id                  = tencentcloud_vpc.vpc.id
  cluster_max_pod_num     = 32
  cluster_name            = "test"
  cluster_desc            = "test cluster desc"
  cluster_max_service_num = 256
  cluster_internet        = true
  cluster_deploy_type     = "MANAGED_CLUSTER"
  network_type            = "VPC-CNI"
  eni_subnet_ids          = ["subnet-bk1etlyu"]
  service_cidr            = "10.1.0.0/24"

  worker_config {
    count                      = 1
    availability_zone          = "ap-guangzhou-7"
    instance_type              = "S2.LARGE16"
    system_disk_type           = "CLOUD_PREMIUM"
    system_disk_size           = 60
    internet_charge_type       = "TRAFFIC_POSTPAID_BY_HOUR"
    internet_max_bandwidth_out = 100
    public_ip_assigned         = true
    subnet_id                  = "subnet-t5dv27rs"

    data_disk {
      disk_type = "CLOUD_PREMIUM"
      disk_size = 50
    }

    enhanced_security_service = false
    enhanced_monitor_service  = false
  }

  log_agent {
    enabled = false
  }

  labels = {
    "test1" = "test1",
    "test2" = "test2",
  }
}

```