resource "google_container_cluster" "bad_example" {
  name     = "bad-cluster"
  location = "us-central1"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "0.0.0.0/0" # ❌ Public access
    }
  }
}
