---
title: "OSLogin is disabled for VM instance"
group_id: "Terraform / GCP"
meta:
  name: "gcp/os_login_is_disabled_for_vm_instance"
  id: "d0b4d550-c001-46c3-bbdb-d5d75d33f05f"
  display_name: "OSLogin is disabled for VM instance"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `d0b4d550-c001-46c3-bbdb-d5d75d33f05f`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance)

### Description

 This check ensures that the `enable-oslogin` metadata attribute is set to `true` on Google Compute Engine VM instances. Disabling OS Login (`enable-oslogin = "FALSE"`) allows users to manage SSH keys directly in instance metadata, which can lead to inconsistent access controls and make it harder to track or revoke user access. By setting `enable-oslogin` to `true`, as shown below, you centralize SSH access management through IAM, improving auditability and reducing the risk of unauthorized access.

```
metadata = {
  enable-oslogin = true
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

    # or if not undefined
    enable-oslogin = true
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

    enable-oslogin = "FALSE"
  }

  metadata_startup_script = "echo hi > /test.txt"

  service_account {
    scopes = ["userinfo-email", "compute-ro", "storage-ro"]
  }
}

```