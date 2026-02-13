---
title: "Launch template is not encrypted"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/launch_template_is_not_encrypted"
  id: "1455cb21-1d48-46d6-8ae3-cef911b71fd5"
  display_name: "Launch template is not encrypted"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Encryption"
---
## Metadata

**Id:** `1455cb21-1d48-46d6-8ae3-cef911b71fd5`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Encryption

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/launch_template#encrypted)

### Description

ECS Launch Template resources must have instance disk data encrypted. To enable encryption, the `encrypted` attribute on the `alicloud_launch_template` resource must be set to `true`. If `encrypted` is `false` or not defined, the resource is non-compliant and should be updated to include `encrypted = true`.

## Compliant Code Examples
```terraform
data "alicloud_images" "images" {
  owners = "system"
}

data "alicloud_instances" "instances" {
}

resource "alicloud_launch_template" "templateneg1" {
  name                          = "tf-test-template"
  description                   = "test1"
  image_id                      = data.alicloud_images.images.images[0].id
  host_name                     = "tf-test-host"
  instance_charge_type          = "PrePaid"
  instance_name                 = "tf-instance-name"
  instance_type                 = data.alicloud_instances.instances.instances[0].instance_type
  internet_charge_type          = "PayByBandwidth"
  internet_max_bandwidth_in     = 5
  internet_max_bandwidth_out    = 0
  io_optimized                  = "none"
  key_pair_name                 = "test-key-pair"
  ram_role_name                 = "xxxxx"
  network_type                  = "vpc"
  security_enhancement_strategy = "Active"
  spot_price_limit              = 5
  spot_strategy                 = "SpotWithPriceLimit"
  security_group_id             = "sg-zxcvj0lasdf102350asdf9a"
  system_disk_category          = "cloud_ssd"
  system_disk_description       = "test disk"
  system_disk_name              = "hello"
  system_disk_size              = 40
  resource_group_id             = "rg-zkdfjahg9zxncv0"
  userdata                      = "xxxxxxxxxxxxxx"
  vswitch_id                    = "sw-ljkngaksdjfj0nnasdf"
  vpc_id                        = "vpc-asdfnbg0as8dfk1nb2"
  zone_id                       = "beijing-a"
  encrypted                     = true

  tags = {
    tag1 = "hello"
    tag2 = "world"
  }
  network_interfaces {
    name              = "eth0"
    description       = "hello1"
    primary_ip        = "10.0.0.2"
    security_group_id = "xxxx"
    vswitch_id        = "xxxxxxx"
  }
  data_disks {
    name        = "disk1"
    description = "test1"
  }
  data_disks {
    name        = "disk2"
    description = "test2"
  }
}

```
## Non-Compliant Code Examples
```terraform
data "alicloud_images" "images" {
  owners = "system"
}

data "alicloud_instances" "instances" {
}

resource "alicloud_launch_template" "templatepos2" {
  name                          = "tf-test-template"
  description                   = "test1"
  image_id                      = data.alicloud_images.images.images[0].id
  host_name                     = "tf-test-host"
  instance_charge_type          = "PrePaid"
  instance_name                 = "tf-instance-name"
  instance_type                 = data.alicloud_instances.instances.instances[0].instance_type
  internet_charge_type          = "PayByBandwidth"
  internet_max_bandwidth_in     = 5
  internet_max_bandwidth_out    = 0
  io_optimized                  = "none"
  key_pair_name                 = "test-key-pair"
  ram_role_name                 = "xxxxx"
  network_type                  = "vpc"
  security_enhancement_strategy = "Active"
  spot_price_limit              = 5
  spot_strategy                 = "SpotWithPriceLimit"
  security_group_id             = "sg-zxcvj0lasdf102350asdf9a"
  system_disk_category          = "cloud_ssd"
  system_disk_description       = "test disk"
  system_disk_name              = "hello"
  system_disk_size              = 40
  resource_group_id             = "rg-zkdfjahg9zxncv0"
  userdata                      = "xxxxxxxxxxxxxx"
  vswitch_id                    = "sw-ljkngaksdjfj0nnasdf"
  vpc_id                        = "vpc-asdfnbg0as8dfk1nb2"
  zone_id                       = "beijing-a"

  tags = {
    tag1 = "hello"
    tag2 = "world"
  }
  network_interfaces {
    name              = "eth0"
    description       = "hello1"
    primary_ip        = "10.0.0.2"
    security_group_id = "xxxx"
    vswitch_id        = "xxxxxxx"
  }
  data_disks {
    name        = "disk1"
    description = "test1"
  }
  data_disks {
    name        = "disk2"
    description = "test2"
  }
}

```

```terraform
data "alicloud_images" "images" {
  owners = "system"
}

data "alicloud_instances" "instances" {
}

resource "alicloud_launch_template" "templatepos1" {
  name                          = "tf-test-template"
  description                   = "test1"
  image_id                      = data.alicloud_images.images.images[0].id
  host_name                     = "tf-test-host"
  instance_charge_type          = "PrePaid"
  instance_name                 = "tf-instance-name"
  instance_type                 = data.alicloud_instances.instances.instances[0].instance_type
  internet_charge_type          = "PayByBandwidth"
  internet_max_bandwidth_in     = 5
  internet_max_bandwidth_out    = 0
  io_optimized                  = "none"
  key_pair_name                 = "test-key-pair"
  ram_role_name                 = "xxxxx"
  network_type                  = "vpc"
  security_enhancement_strategy = "Active"
  spot_price_limit              = 5
  spot_strategy                 = "SpotWithPriceLimit"
  security_group_id             = "sg-zxcvj0lasdf102350asdf9a"
  system_disk_category          = "cloud_ssd"
  system_disk_description       = "test disk"
  system_disk_name              = "hello"
  system_disk_size              = 40
  resource_group_id             = "rg-zkdfjahg9zxncv0"
  userdata                      = "xxxxxxxxxxxxxx"
  vswitch_id                    = "sw-ljkngaksdjfj0nnasdf"
  vpc_id                        = "vpc-asdfnbg0as8dfk1nb2"
  zone_id                       = "beijing-a"
  encrypted                     = false

  tags = {
    tag1 = "hello"
    tag2 = "world"
  }
  network_interfaces {
    name              = "eth0"
    description       = "hello1"
    primary_ip        = "10.0.0.2"
    security_group_id = "xxxx"
    vswitch_id        = "xxxxxxx"
  }
  data_disks {
    name        = "disk1"
    description = "test1"
  }
  data_disks {
    name        = "disk2"
    description = "test2"
  }
}

```