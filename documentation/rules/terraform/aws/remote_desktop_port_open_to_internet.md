---
title: "Remote Desktop port open to internet"
group_id: "Terraform / AWS"
meta:
  name: "aws/remote_desktop_port_open_to_internet"
  id: "151187cb-0efc-481c-babd-ad24e3c9bc22"
  display_name: "Remote Desktop port open to internet"
  cloud_provider: "AWS"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `151187cb-0efc-481c-babd-ad24e3c9bc22`

**Cloud Provider:** AWS

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)

### Description

This check identifies AWS Security Groups that have Remote Desktop ports (commonly in ranges 3380-3450) exposed to the internet via '0.0.0.0/0' or similar CIDR blocks. Exposing Remote Desktop ports to the public internet creates a significant security risk as it allows potential attackers to attempt brute-force attacks against your instances. Instead, restrict access to specific trusted IP ranges or use a bastion host/VPN for secure remote access.

Secure example:
```terraform
ingress {
  description = "Remote desktop open private"
  from_port   = 3380
  to_port     = 3450
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]  // Restricted to private network
}
```

Insecure example:
```terraform
ingress {
  description = "Remote desktop port open"
  from_port   = 3380
  to_port     = 3450
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  // Open to the internet
}
```

## Compliant Code Examples
```terraform
resource "aws_security_group" "negative1" {
  name        = "Dont open remote desktop port"
  description = "Doesn't enable the remote desktop port"

}

resource "aws_security_group" "negative2" {

  ingress {
    description = "Remote desktop open private"
    from_port   = 3380
    to_port     = 3450
    protocol    = "tcp"
  }
}

resource "aws_security_group" "negative_rdp_2" {

  ingress {
    description = "Remote desktop open private"
    from_port   = 3380
    to_port     = 3450
    protocol    = "tcp"
    cidr_blocks = ["0.1.0.0/0"]
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "aws_security_group" "positive1" {
  name        = "rdp_positive_tcp_1"
  description = "Gets the remote desktop port open with the tcp protocol"

  ingress {
    description = "Remote desktop port open"
    from_port   = 3380
    to_port     = 3450
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "positive2" {
  name        = "rdp_positive_tcp_2"
  description = "Gets the remote desktop port open with the tcp protocol"

  ingress {
    description = "Remote desktop port open"
    from_port   = 3381
    to_port     = 3445
    protocol    = "tcp"
    cidr_blocks = ["1.0.0.0/0"]
  }

  ingress {
    description = "Remote desktop port open"
    from_port   = 3000
    to_port     = 4000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

```