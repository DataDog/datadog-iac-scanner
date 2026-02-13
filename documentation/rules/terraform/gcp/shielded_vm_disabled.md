---
title: "Shielded VM disabled"
group_id: "Terraform / GCP"
meta:
  name: "gcp/shielded_vm_disabled"
  id: "1b44e234-3d73-41a8-9954-0b154135280e"
  display_name: "Shielded VM disabled"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `1b44e234-3d73-41a8-9954-0b154135280e`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance#shielded_instance_config)

### Description

 Compute instances must be configured with Shielded VM enabled to provide enhanced security against rootkits and other persistent threats. This requires defining the `shielded_instance_config` block with all sub-attributes—`enable_secure_boot`, `enable_vtpm`, and `enable_integrity_monitoring`—set to `true`. Failure to enable these features, as shown below, can leave virtual machines vulnerable to unauthorized modifications, tampering, or attacks that compromise the integrity and confidentiality of the system.

```
data "google_compute_instance" "appserver" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_secure_boot = true
      enable_vtpm = true
      enable_integrity_monitoring = true
  }
}
```


## Compliant Code Examples
```terraform
#this code is a correct code for which the query should not find any result
data "google_compute_instance" "appserver" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_secure_boot = true
      enable_vtpm = true
      enable_integrity_monitoring = true
  }
}
```
## Non-Compliant Code Examples
```terraform
#this is a problematic code where the query should report a result(s)
data "google_compute_instance" "appserver1" {
  name = "primary-application-server"
  zone = "us-central1-a"
}

data "google_compute_instance" "appserver2" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_secure_boot = true
      enable_vtpm = true
  }
}

data "google_compute_instance" "appserver3" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_secure_boot = true
      enable_integrity_monitoring = true
  }
}

data "google_compute_instance" "appserver4" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_vtpm = true
      enable_integrity_monitoring = true
  }
}

data "google_compute_instance" "appserver5" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_secure_boot = false
      enable_vtpm = true
      enable_integrity_monitoring = true
  }
}

data "google_compute_instance" "appserver6" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_secure_boot = true
      enable_vtpm = false
      enable_integrity_monitoring = true
  }
}

data "google_compute_instance" "appserver7" {
  name = "primary-application-server"
  zone = "us-central1-a"
  shielded_instance_config {
      enable_secure_boot = true
      enable_vtpm = true
      enable_integrity_monitoring = false
  }
}
```

```terraform
resource "google_compute_instance" "jumpbox" {
  name         = "${var.name}-jumpbox"
  machine_type = var.instance_type
  zone         = element(var.zones, 0)

  boot_disk {
    initialize_params {
      image = "${var.images_source}/${var.image_family}"
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  network_interface {
    subnetwork = var.subnet
  }

  metadata = {}

  service_account {
    scopes = []
  }

  tags = ["public", "jumpbox"]
}

resource "google_compute_firewall" "jumpbox" {
  name    = "${var.name}-ssh-to-jumpbox"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_tags = ["appgate-gateway"]

  target_tags = ["jumpbox"]
}

resource "google_compute_firewall" "jumpbox_service" {
  name    = "${var.name}-jumpbox-service"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443"]
  }

  source_tags = ["jumpbox"]

  target_tags = ["jumpbox-service"]
}

```