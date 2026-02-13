resource "google_container_cluster" "good_example" {
  name     = "good-cluster"
  location = "us-central1"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "10.0.0.0/8" # ✅ Private network only
    }
  }
}
