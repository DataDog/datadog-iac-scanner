---
title: "Public security group rule unknown port"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/public_security_group_rule_unknown_port"
  id: "dd706080-b7a8-47dc-81fb-3e8184430ec0"
  display_name: "Public security group rule unknown port"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `dd706080-b7a8-47dc-81fb-3e8184430ec0`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/security_group_rule#port_range)

### Description

 An unknown port, such as `24` or `111`, is open to the public on the `tcp`, `udp`, or `all` protocol. This occurs when `port_range` includes ports not present in the known ports map and `cidr_ip` is set to `0.0.0.0/0`. Such security group rules expose services to the entire Internet and should be avoided.


## Compliant Code Examples
```terraform
resource "alicloud_security_group" "default" {
  name = "default"
}

resource "alicloud_security_group_rule" "allow_all_tcp" {
  type              = "ingress"
  ip_protocol       = "icmp"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "-1/-1"
  priority          = 1
  security_group_id = alicloud_security_group.default.id
  cidr_ip           = "10.159.6.18/12"
}

```

```terraform
resource "alicloud_security_group" "default" {
  name = "default"
}

resource "alicloud_security_group_rule" "allow_all_tcp" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "1/65535"
  priority          = 1
  security_group_id = alicloud_security_group.default.id
  cidr_ip           = "10.159.6.18/12"
}

```
## Non-Compliant Code Examples
```terraform
resource "alicloud_security_group" "default" {
  name = "default"
}

resource "alicloud_security_group_rule" "allow_all_tcp" {
  type              = "ingress"
  ip_protocol       = "all"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "-1/-1"
  priority          = 1
  security_group_id = alicloud_security_group.default.id
  cidr_ip           = "0.0.0.0/0"
}

```

```terraform
resource "alicloud_security_group" "default" {
  name = "default"
}

resource "alicloud_security_group_rule" "allow_all_tcp" {
  type              = "ingress"
  ip_protocol       = "tcp"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "54/60"
  priority          = 1
  security_group_id = alicloud_security_group.default.id
  cidr_ip           = "0.0.0.0/0"
}

```