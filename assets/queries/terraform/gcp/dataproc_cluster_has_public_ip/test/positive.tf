resource "google_dataproc_cluster" "bad_example" {
  name   = "bad-cluster"
  region = "us-central1"

  cluster_config {
    gce_cluster_config {
      internal_ip_only = false # ❌ Public IP enabled
    }
  }
}
