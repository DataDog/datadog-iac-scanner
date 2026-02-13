---
title: "IP forwarding enabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/ip_forwarding_enabled"
  id: "f34c0c25-47b4-41eb-9c79-249b4dd47b89"
  display_name: "IP forwarding enabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `f34c0c25-47b4-41eb-9c79-249b4dd47b89`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/data-sources/compute_instance)

### Description

This check ensures that the `can_ip_forward` attribute for Google Compute Engine instances is set to `false`, which prevents instances from forwarding packets not addressed to them. If `can_ip_forward` is set to `true`, as shown below, the instance could be misused as a routing or proxy device, increasing the risk of data exfiltration or man-in-the-middle attacks:

```
resource "google_compute_instance" "appserver" {
  name           = "primary-application-server"
  machine_type   = "e2-medium"
  can_ip_forward = true
  ...
}
```

To mitigate this risk, configure the attribute as `false`:

```
resource "google_compute_instance" "appserver" {
  name           = "primary-application-server"
  machine_type   = "e2-medium"
  can_ip_forward = false
  ...
}
```
Disabling IP forwarding hardens network boundaries and reduces the attack surface of the cloud environment.

## Compliant Code Examples
```terraform
resource "google_compute_instance" "appserver" {
  name           = "primary-application-server"
  machine_type   = "e2-medium"
  can_ip_forward = false

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_compute_instance" "appserver" {
  name           = "primary-application-server"
  machine_type   = "e2-medium"
  can_ip_forward = true

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"
  }
}

```