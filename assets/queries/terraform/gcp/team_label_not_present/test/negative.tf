resource "google_compute_instance" "good_example" {
  name         = "good-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }

  labels = {
    team        = "DevOps" # ✅ "team" tag is present
    environment = "prod"
  }
}
