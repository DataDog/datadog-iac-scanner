resource "google_compute_firewall" "bad_example" {
  name    = "bad-firewall"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["21"]
  }

  source_ranges = ["0.0.0.0/0"] # Unrestricted ingress for FTP
}
