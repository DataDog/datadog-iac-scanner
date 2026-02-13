---
title: "Serial ports are enabled for VM instances"
group_id: "Terraform / GCP"
meta:
  name: "gcp/vm_serial_ports_are_enabled_for_vm_instances"
  id: "97fa667a-d05b-4f16-9071-58b939f34751"
  display_name: "Serial ports are enabled for VM instances"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `97fa667a-d05b-4f16-9071-58b939f34751`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance)

### Description

Google Compute Engine VM instances should not have serial ports enabled. Enabling serial ports by setting the `serial-port-enable` metadata attribute to `true` (as shown below) can allow anyone with the username, project ID, SSH key, instance name, and zone to directly access the VM, increasing the risk of unauthorized access and potential compromise.

```
metadata = {
  serial-port-enable = true
}
```

To mitigate this risk, set `serial-port-enable` to `false` to ensure that serial port access is disabled and remote attackers cannot exploit this vector:

```
metadata = {
  serial-port-enable = false
}
```

## Compliant Code Examples
```terraform
resource "google_compute_instance" "negative1" {
  name         = "test"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  tags = ["foo", "bar"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
  }

  scratch_disk {
    interface = "SCSI"
  }

  network_interface {
    network = "default"

    access_config {
    }
  }

  metadata = {
    serial-port-enable = "FALSE"
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    scopes = ["userinfo-email", "compute-ro", "storage-ro"]
  }
}

resource "google_compute_project_metadata" "negative2" {
  metadata = {
    serial-port-enable = false
  }
}

resource "google_compute_project_metadata_item" "negative3" {
  key   = "my_metadata"
  value = "my_value"
}

```
## Non-Compliant Code Examples
```terraform
resource "google_compute_instance" "positive1" {
  name         = "test"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  tags = ["foo", "bar"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
  }

  scratch_disk {
    interface = "SCSI"
  }

  network_interface {
    network = "default"

    access_config {
    }
  }

  metadata = {
    serial-port-enable = true
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    scopes = ["userinfo-email", "compute-ro", "storage-ro"]
  }
}

resource "google_compute_project_metadata" "positive2" {
  metadata = {
    serial-port-enable = "TRUE"
  }
}

resource "google_compute_project_metadata_item" "positive3" {
  key   = "serial-port-enable"
  value = "TRUE"
}

```