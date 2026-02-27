---
title: "RDP access is not restricted"
group_id: "Terraform / GCP"
meta:
  name: "gcp/rdp_access_is_not_restricted"
  id: "678fd659-96f2-454a-a2a0-c2571f83a4a3"
  display_name: "RDP access is not restricted"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "HIGH"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `678fd659-96f2-454a-a2a0-c2571f83a4a3`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** High

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall)

### Description

This check verifies if Google Compute firewall rules allow unrestricted RDP access by examining if port 3389 (the default RDP port) is openly accessible from the internet. When firewall rules allow RDP traffic from `0.0.0.0/0` (all IPv4) or `::/0` (all IPv6), it significantly increases the risk of brute force attacks, unauthorized access, and potential system compromise.

Vulnerable configurations include allowing port 3389 directly or within ranges (for example, `21-3390`), or using `protocol = "all"` with unrestricted source ranges. To secure your environment, explicitly exclude RDP ports from public access and restrict RDP traffic to specific trusted IP addresses or VPN connections.

```hcl
// Insecure configuration (AVOID):
resource "google_compute_firewall" "insecure" {
  // ... other configuration ...
  allow {
    protocol = "tcp"
    ports    = ["80", "3389"]
  }
  source_ranges = ["0.0.0.0/0"]
}

// Secure configuration:
resource "google_compute_firewall" "secure" {
  // ... other configuration ...
  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "1000-2000"] // Excludes RDP port 3389
  }
  source_tags = ["web"]
  // Alternatively, limit RDP to specific IPs:
  // source_ranges = ["10.0.0.0/24", "192.168.1.0/24"]
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

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "1000-2000","3389"]
  }

  source_tags = ["web"]
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "positive2" {
  name    = "test-firewall"
  network = google_compute_network.default.name

  allow {
    protocol = "udp"
    ports    = ["80", "8080", "1000-2000","21-3390"]
  }

  source_tags = ["web"]
  source_ranges = ["::/0"]
}

resource "google_compute_firewall" "positive3" {
  name    = "test-firewall"
  network = google_compute_network.default.name

  allow {
    protocol = "all"
  }

  source_tags = ["web"]
  source_ranges = ["::/0"]
}

```