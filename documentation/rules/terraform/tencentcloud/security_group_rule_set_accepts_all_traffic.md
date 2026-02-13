---
title: "Beta - security group rule set accepts all traffic"
group_id: "Terraform / TencentCloud"
meta:
  name: "tencentcloud/security_group_rule_set_accepts_all_traffic"
  id: "d135a36e-c474-452f-b891-76db1e6d1cd5"
  display_name: "Beta - security group rule set accepts all traffic"
  cloud_provider: "TencentCloud"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `d135a36e-c474-452f-b891-76db1e6d1cd5`

**Cloud Provider:** TencentCloud

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud/latest/docs/resources/security_group_rule_set#ingress)

### Description

`tencentcloud_security_group_rule_set` `ingress` is configured to accept all traffic.  
This rule triggers when an `ingress` entry has `action` set to `ACCEPT` and the source is `cidr_block` = `0.0.0.0/0` (IPv4) or `ipv6_cidr_block` = `::/0` (IPv6), with `protocol` = `ALL` and `port` = `ALL`.  
`tencentcloud_security_group_rule_set` `ingress` should not be set to accept all traffic.

## Compliant Code Examples
```terraform
resource "tencentcloud_security_group" "sg" {
  name        = "tf-example"
  description = "Testing Rule Set Security"
}

resource "tencentcloud_security_group_rule_set" "base" {
  security_group_id = tencentcloud_security_group.sg.id
}

```

```terraform
resource "tencentcloud_security_group" "sg" {
  name        = "tf-example"
  description = "Testing Rule Set Security"
}

resource "tencentcloud_security_group_rule_set" "base" {
  security_group_id = tencentcloud_security_group.sg.id

  ingress {
    action      = "ACCEPT"
    cidr_block  = "10.0.0.0/22"
    protocol    = "TCP"
    port        = "80-90"
    description = "A:Allow Ips and 80-90"
  }

  egress {
    action      = "DROP"
    cidr_block  = "10.0.0.0/16"
    protocol    = "ICMP"
    description = "A:Block ping3"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "tencentcloud_security_group" "sg" {
  name        = "tf-example"
  description = "Testing Rule Set Security"
}

resource "tencentcloud_security_group_rule_set" "base" {
  security_group_id = tencentcloud_security_group.sg.id

  ingress {
    action     = "ACCEPT"
    cidr_block = "0.0.0.0/0"
  }
}

```

```terraform
resource "tencentcloud_security_group" "sg" {
  name        = "tf-example"
  description = "Testing Rule Set Security"
}

resource "tencentcloud_security_group_rule_set" "base" {
  security_group_id = tencentcloud_security_group.sg.id

  ingress {
    action          = "ACCEPT"
    ipv6_cidr_block = "::/0"
    protocol        = "ALL"
    port            = "ALL"
  }
}

```

```terraform
resource "tencentcloud_security_group" "sg" {
  name        = "tf-example"
  description = "Testing Rule Set Security"
}

resource "tencentcloud_security_group_rule_set" "base" {
  security_group_id = tencentcloud_security_group.sg.id

  ingress {
    action          = "ACCEPT"
    ipv6_cidr_block = "::/0"
  }
}

```