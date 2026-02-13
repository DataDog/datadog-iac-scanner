resource "google_compute_network" "modern_network" {
  name                    = "modern-network"
  auto_create_subnetworks = false
}
