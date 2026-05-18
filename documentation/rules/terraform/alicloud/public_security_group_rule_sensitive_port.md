---
title: "Public security group rule sensitive port"
group_id: "Terraform / Alicloud"
meta:
  name: "alicloud/public_security_group_rule_sensitive_port"
  id: "terraform-alicloud-public-security-group-rule-sensitive-port"
  display_name: "Public security group rule sensitive port"
  cloud_provider: "Alicloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** {{< copyable-code >}}terraform-alicloud-public-security-group-rule-sensitive-port{{< /copyable-code >}}

**Cloud Provider:** Alicloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/aliyun/alicloud/latest/docs/resources/security_group_rule#port_range)

### Description

A sensitive port, such as `23` or `110`, is open to the public using `TCP` or `UDP`. This rule detects ingress `alicloud_security_group_rule` resources where `cidr_ip` is set to `0.0.0.0/0`, the `protocol` is `tcp`, `udp`, or `all`, and the `port_range` includes a known sensitive port. This configuration exposes the service to the public internet and increases the risk of unauthorized access.

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
  ip_protocol       = "udp"
  nic_type          = "internet"
  policy            = "accept"
  port_range        = "4333/4334"
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
  port_range        = "444/445"
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
  port_range        = "19/20"
  priority          = 1
  security_group_id = alicloud_security_group.default.id
  cidr_ip           = "0.0.0.0/0"
}

```