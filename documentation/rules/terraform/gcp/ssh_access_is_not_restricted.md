---
title: "SSH access is not restricted"
group_id: "Terraform / GCP"
meta:
  name: "gcp/ssh_access_is_not_restricted"
  id: "c4dcdcdf-10dd-4bf4-b4a0-8f6239e6aaa0"
  display_name: "SSH access is not restricted"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `c4dcdcdf-10dd-4bf4-b4a0-8f6239e6aaa0`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall)

### Description

 Allowing SSH access (TCP port 22) from the internet (such as setting `source_ranges = ["0.0.0.0/0"]` in a `google_compute_firewall` resource) exposes virtual machine instances to potential unauthorized access and brute-force attacks, violating the principle of least privilege. Attackers scanning public IP ranges can exploit this misconfiguration to gain direct access to your systems, increasing the risk of compromise. A secure configuration should restrict SSH access to trusted IP addresses or private networks, as shown below:

```
resource "google_compute_firewall" "secure_example" {
  name    = "restricted-ssh"
  network = google_compute_network.default.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["203.0.113.0/24"] // Replace with trusted IP range
  source_tags = ["admin"]
}
```


## Compliant Code Examples
```terraform
resource "google_compute_firewall" "negative1" {
  name    = "test-firewall"
  network = google_compute_network.default.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "1000-2000"]
  }

  source_tags = ["web"]
}
```
## Non-Compliant Code Examples
```terraform
resource "google_compute_firewall" "positive1" {
  name    = "test-firewall"
  network = google_compute_network.default.name
  direction = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "3389", "8080", "1000-2000"]
  }

  source_tags = ["web"]
}

resource "google_compute_firewall" "positive2" {
  name    = "test-firewall"
  network = google_compute_network.default.name

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "1000-2000","21-3390"]
  }

  source_tags = ["web"]
}

resource "google_compute_firewall" "positive3" {
  name    = "test-firewall"
  network = google_compute_network.default.name

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "all"
  }

  source_tags = ["web"]
}

```