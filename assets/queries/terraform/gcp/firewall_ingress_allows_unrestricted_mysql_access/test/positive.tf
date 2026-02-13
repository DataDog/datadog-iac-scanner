resource "google_compute_firewall" "bad_example" {
  name    = "bad-firewall-mysql"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["3306"]
  }

  source_ranges = ["0.0.0.0/0"] # Unrestricted ingress for MySQL
}
