---
title: "Team label missing on GCP resource"
group_id: "Terraform / GCP"
meta:
  name: "gcp/team_label_not_present"
  id: "b2b3c4d5-e6f7-8901-gh23-ijkl456m7890"
  display_name: "Team label missing on GCP resource"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "LOW"
  category: "Best Practices"
---
## Metadata

**Id:** `b2b3c4d5-e6f7-8901-gh23-ijkl456m7890`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Low

**Category:** Best Practices

#### Learn More

 - [Provider Reference](https://cloud.google.com/storage/docs/tags-and-labels)

### Description

To ensure accountability and efficient resource management, every cloud resource should include a `team` label identifying ownership. Without this label, as shown in the example below, resources may lack clear ownership, making it difficult to track responsibility for maintenance, cost allocation, or incident response:

```
resource "google_bigtable_instance" "example" {
  name = "my-instance"
}
```

Properly labeling resources with a `team` tag, as in the following example, improves governance and accountability:

```
labels = {
  team = "DevOps"
}
```

Neglecting this can lead to orphaned resources, wasted spend, and slower incident resolution due to unclear points of contact.

## Compliant Code Examples
```terraform
# ✅ "team" label is not a valid attribute for this resource type
resource "google_container_cluster" "good_example" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  monitoring_service = "monitoring.googleapis.com"

  timeouts {
    create = "30m"
    update = "40m"
  }
}

```

```terraform
resource "google_compute_instance" "good_example" {
  name         = "good-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }

  labels = {
    Team        = "DevOps" # ✅ "Team" tag is present
    environment = "prod"
  }
}

```

```terraform
resource "google_compute_instance" "good_example" {
  name         = "good-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }

  labels = {
    team        = "DevOps" # ✅ "team" tag is present
    environment = "prod"
  }
}

```
## Non-Compliant Code Examples
```terraform
resource "google_bigtable_instance" "positive2" {
  name = "marcellus-wallace"
  timeouts {
    create = "30m"
    update = "40m"
  }
}

resource "google_compute_instance" "good_example_2" {
  name         = "good-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }

  labels = {
    environment = "prod"
  }
}

```