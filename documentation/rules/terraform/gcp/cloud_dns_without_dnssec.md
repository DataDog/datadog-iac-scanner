---
title: "Cloud DNS without DNSSEC"
group_id: "Terraform / GCP"
meta:
  name: "gcp/cloud_dns_without_dnssec"
  id: "5ef61c88-bbb4-4725-b1df-55d23c9676bb"
  display_name: "Cloud DNS without DNSSEC"
  cloud_provider: "GCP"
  platform: "Terraform"
  severity: "MEDIUM"
  category: "Insecure Configurations"
---
## Metadata

**Id:** `5ef61c88-bbb4-4725-b1df-55d23c9676bb`

**Cloud Provider:** GCP

**Platform:** Terraform

**Severity:** Medium

**Category:** Insecure Configurations

#### Learn More

 - [Provider Reference](https://www.terraform.io/docs/providers/google/d/dns_managed_zone.html)

### Description

Domain Name System Security Extensions (DNSSEC) should be enabled for Cloud DNS managed zones to ensure the authenticity and integrity of DNS data by cryptographically signing DNS records. Without DNSSEC enabled (for example, `dnssec_config { state = "off" }`), domains are at greater risk of DNS spoofing and cache poisoning attacks, potentially allowing attackers to redirect traffic or intercept sensitive communications. To mitigate this risk, configure DNSSEC as shown below:

```
resource "google_dns_managed_zone" "example" {
  name     = "secure-zone"
  dns_name = "secure.example."

  dnssec_config {
    state         = "on"
    non_existence = "nsec3"
  }
}
```

## Compliant Code Examples
```terraform
resource "google_dns_managed_zone" "negative1" {
  name     = "foobar"
  dns_name = "foo.bar."

  dnssec_config {
    state         = "on"
    non_existence = "nsec3"
  }
}
```
## Non-Compliant Code Examples
```terraform
resource "google_dns_managed_zone" "dns_zone" {
  name        = var.zone_id
  dns_name    = var.name
  description = "managed by Runtime DNA"
  visibility  = length(var.vpc_id) == 0 ? "public" : "private"

  dynamic "private_visibility_config" {
    for_each = length(var.vpc_id) > 0 ? [1] : []
    content {
      dynamic "networks" {
        for_each = toset(var.vpc_id)
        content {
          network_url = networks.value
        }
      }
    }
  }
}

```

```terraform
// comment
// comment
// comment
// comment
resource "google_dns_managed_zone" "positive1" {
  name     = "foobar"
  dns_name = "foo.bar."

  dnssec_config {
    state         = "off"
    non_existence = "nsec3"
  }
}
```

```terraform
resource "google_dns_managed_zone" "target" {
  name        = "postgres-eu1-prod-dog"
  dns_name    = "postgres.eu1.prod.dog."
  description = "delegated from google cloud dns"

  lifecycle {
    ignore_changes = [
      # Ignore changes to DNSSEC, since these resources were changed
      # outside of this terraform configuration
      dnssec_config,
    ]
  }

}

data "google_dns_managed_zone" "source" {
  name = "eu1-prod-dog"
}

resource "google_dns_record_set" "delegate" {
  name         = "postgres.eu1.prod.dog."
  managed_zone = google_dns_managed_zone.target.name

  type = "NS"
  ttl  = 21600

  rrdatas = google_dns_managed_zone.target.name_servers
}

// Override the default SOA record for the zone to lower the negative ttl on NameErrors
// NXDOMAINS and NODATA responses are cached by cloud resolvers for min(soa.minimum_ttl, soa.ttl).
resource "google_dns_record_set" "soa_override" {
  name         = google_dns_managed_zone.target.dns_name
  managed_zone = google_dns_managed_zone.target.name

  type = "SOA"
  ttl  = 300

  rrdatas = ["${google_dns_managed_zone.target.name_servers[0]} cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"]
}

```