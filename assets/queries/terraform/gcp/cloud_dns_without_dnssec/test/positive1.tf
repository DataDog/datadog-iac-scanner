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
