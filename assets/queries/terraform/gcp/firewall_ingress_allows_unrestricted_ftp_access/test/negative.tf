resource "google_compute_firewall" "good_example" {
  name    = "good-firewall"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["21"]
  }

  source_ranges = ["192.168.1.0/24"] # Restricted ingress for FTP
}
