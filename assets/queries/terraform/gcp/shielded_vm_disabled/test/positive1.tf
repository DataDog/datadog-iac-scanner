resource "google_compute_instance" "jumpbox" {
  name         = "${var.name}-jumpbox"
  machine_type = var.instance_type
  zone         = element(var.zones, 0)

  boot_disk {
    initialize_params {
      image = "${var.images_source}/${var.image_family}"
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  network_interface {
    subnetwork = var.subnet
  }

  metadata = {}

  service_account {
    scopes = []
  }

  tags = ["public", "jumpbox"]
}

resource "google_compute_firewall" "jumpbox" {
  name    = "${var.name}-ssh-to-jumpbox"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_tags = ["appgate-gateway"]

  target_tags = ["jumpbox"]
}

resource "google_compute_firewall" "jumpbox_service" {
  name    = "${var.name}-jumpbox-service"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443"]
  }

  source_tags = ["jumpbox"]

  target_tags = ["jumpbox-service"]
}
