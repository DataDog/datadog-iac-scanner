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
