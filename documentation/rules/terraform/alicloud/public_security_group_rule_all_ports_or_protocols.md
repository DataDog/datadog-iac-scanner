---
title: "Public security group rule all ports or protocols"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/public_security_group_rule_all_ports_or_protocols"
  id: "60587dbd-6b67-432e-90f7-a8cf1892d968"
  display_name: "Public security group rule all ports or protocols"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `60587dbd-6b67-432e-90f7-a8cf1892d968`

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/security_group_rule#cidr_ip)

### Description

Alicloud security group rules must not expose all ports or all protocols to the public. This rule flags `alicloud_security_group_rule` resources where:

- `cidr_ip` is `0.0.0.0/0` and `ip_protocol` is `all`, or
- `ip_protocol` is `tcp` or `udp` and `port_range` is `1/65535`, or
- `ip_protocol` is `icmp` or `gre` and `port_range` is `-1/-1`

These configurations expose resources to the public internet and significantly increase the attack surface.

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
  ip_protocol       = "gre"
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
  port_range        = "1/65535"
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
  ip_protocol       = "all"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "-1/-1"
  priority          = 1
  security_group_id = alicloud_security_group.default.id
  cidr_ip           = "0.0.0.0/0"
}

```