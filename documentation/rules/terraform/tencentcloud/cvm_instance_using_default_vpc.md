---
title: "Beta - CVM instance using default VPC"
group_id: "Terraform / TencentCloud"
meta:
  name: "tencentcloud/cvm_instance_using_default_vpc"
  id: "b4e75c5c-83d5-4568-90e3-57ed5ec4051b"
  display_name: "Beta - CVM instance using default VPC"
  cloud_provider: "TencentCloud"
  platform: "Terraform"
  severity: "LOW"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `b4e75c5c-83d5-4568-90e3-57ed5ec4051b`

**Cloud Provider:** TencentCloud

**Platform:** Terraform

**Severity:** Low

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs/resources/instance#vpc_id)

### Description

 CVM instances should not be configured in the default VPC network. The `vpc_id` attribute of a `tencentcloud_instance` should not be set to `default`. Additionally, the `subnet_id` should not reference a default subnet.


## Compliant Code Examples
```terraform
resource "tencentcloud_vpc" "vpc" {
  name       = "tf_example"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_subnet" "subnet" {
  name              = "tf_example"
  vpc_id            = tencentcloud_vpc.vpc.id
  availability_zone = "ap-guangzhou-7"
  cidr_block        = "10.0.1.0/24"
}

resource "tencentcloud_instance" "cvm_postpaid" {
  instance_name     = "cvm_postpaid"
  availability_zone = "ap-guangzhou-7"
  image_id          = "img-9qrfy1xt"
  instance_type     = "SA2.MEDIUM4"
  system_disk_type  = "CLOUD_PREMIUM"
  system_disk_size  = 50
  hostname          = "user"
  project_id        = 0
  vpc_id            = tencentcloud_vpc.vpc.id
  subnet_id         = tencentcloud_subnet.subnet.id

  data_disks {
    data_disk_type = "CLOUD_PREMIUM"
    data_disk_size = 50
    encrypt        = false
  }

  tags = {
    tagKey = "tagValue"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "tencentcloud_vpc" "default" {
  name       = "tf_example"
  cidr_block = "10.0.0.0/16"
}

resource "tencentcloud_subnet" "default" {
  name              = "tf_example"
  vpc_id            = tencentcloud_vpc.vpc.id
  availability_zone = "ap-guangzhou-7"
  cidr_block        = "10.0.1.0/24"
}

resource "tencentcloud_instance" "cvm_postpaid" {
  instance_name     = "cvm_postpaid"
  availability_zone = "ap-guangzhou-7"
  image_id          = "img-9qrfy1xt"
  instance_type     = "SA2.MEDIUM4"
  system_disk_type  = "CLOUD_PREMIUM"
  system_disk_size  = 50
  hostname          = "user"
  project_id        = 0
  vpc_id            = tencentcloud_vpc.default.id
  subnet_id         = tencentcloud_subnet.default.id

  data_disks {
    data_disk_type = "CLOUD_PREMIUM"
    data_disk_size = 50
    encrypt        = false
  }

  tags = {
    tagKey = "tagValue"
  }
}

```