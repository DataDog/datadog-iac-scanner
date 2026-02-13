resource "google_compute_network" "legacy_network" {
  name                    = "legacy-network"
  auto_create_subnetworks = true
}
