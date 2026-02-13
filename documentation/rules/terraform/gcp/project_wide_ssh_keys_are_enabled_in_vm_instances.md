---
title: "Project-wide SSH keys are enabled in VM instances"
group_id: "Terraform / GCP"
meta:
  name: "gcp/project_wide_ssh_keys_are_enabled_in_vm_instances"
  id: "3e4d5ce6-3280-4027-8010-c26eeea1ec01"
  display_name: "Project-wide SSH keys are enabled in VM instances"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Secret Management"
---
## Metadata

**Id:** `3e4d5ce6-3280-4027-8010-c26eeea1ec01`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Secret Management

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance)

### Description

 This check ensures that Google Compute Engine VM instances have project-wide SSH keys blocked by setting the metadata attribute `block-project-ssh-keys` to `"TRUE"`. Without this setting, anyone with project-level SSH key access can connect to the VM, increasing the risk of unauthorized access and making it harder to manage individual SSH permissions. For a secure configuration, define the attribute in your Terraform configuration as follows:

```
metadata = {
  block-project-ssh-keys = "TRUE"
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

  // Local SSD disk
  scratch_disk {
    interface = "SCSI"
  }

  network_interface {
    network = "default"

    access_config {
      // Ephemeral IP
    }
  }

  metadata = {
    #... some other metadata
    
    block-project-ssh-keys = "TRUE"
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    scopes = ["userinfo-email", "compute-ro", "storage-ro"]
  }
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

  // Local SSD disk
  scratch_disk {
    interface = "SCSI"
  }

  network_interface {
    network = "default"

    access_config {
      // Ephemeral IP
    }
  }

  metadata = {
    #... some other metadata
    block-project-ssh-keys = false
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    scopes = ["userinfo-email", "compute-ro", "storage-ro"]
  }
}

resource "google_compute_instance" "positive2" {
  name         = "test"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  tags = ["foo", "bar"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
  }

  // Local SSD disk
  scratch_disk {
    interface = "SCSI"
  }

  network_interface {
    network = "default"

    access_config {
      // Ephemeral IP
    }
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    scopes = ["userinfo-email", "compute-ro", "storage-ro"]
  }
}


```