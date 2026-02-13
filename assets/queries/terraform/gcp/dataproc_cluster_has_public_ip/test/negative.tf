resource "google_dataproc_cluster" "good_example" {
  name   = "good-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      internal_ip_only = true # ✅ Private cluster (no public IP)
    }
  }
}
