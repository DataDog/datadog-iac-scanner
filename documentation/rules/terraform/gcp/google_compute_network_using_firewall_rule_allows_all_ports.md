---
title: "Google Compute network using firewall rule that allows all ports"
group_id: "Terraform / GCP"
meta:
  name: "gcp/google_compute_network_using_firewall_rule_allows_all_ports"
  id: "22ef1d26-80f8-4a6c-8c15-f35aab3cac78"
  display_name: "Google Compute network using firewall rule that allows all ports"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Networking and Firewall"
---
## Metadata

**Id:** `22ef1d26-80f8-4a6c-8c15-f35aab3cac78`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Networking and Firewall

#### Learn More

 - [Provider Reference](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#allow)

### Description

Allowing a Google Compute Network firewall rule to permit traffic on all TCP ports (using `ports = ["0-65535"]`) exposes instances to a broad range of attacks and unauthorized access, increasing the risk of exploitation across unused and potentially vulnerable services. By not restricting allowed ports to only those necessary—such as `ports = ["80", "8080"]` for web services—the configuration creates a large attack surface. To minimize security risks, firewall rules should define only the specific protocols and ports required for service functionality.

## Compliant Code Examples
```terraform
resource "google_compute_firewall" "negative1" {
  name    = "test-firewall"
  network = google_compute_network.negative1.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["80", "8080"]
  }

  source_tags = ["web"]
}

resource "google_compute_network" "negative1" {
  name = "test-network"
}

```
## Non-Compliant Code Examples
```terraform
resource "google_compute_firewall" "positive1" {
  name    = "test-firewall"
  network = google_compute_network.positive1.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_tags = ["web"]
}

resource "google_compute_network" "positive1" {
  name = "test-network"
}

```