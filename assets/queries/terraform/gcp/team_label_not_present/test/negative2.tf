# ✅ "team" label is not a valid attribute for this resource type
resource "google_container_cluster" "good_example" {
  name               = "marcellus-wallace"
  location           = "us-central1-a"
  initial_node_count = 3
  monitoring_service = "monitoring.googleapis.com"

  timeouts {
    create = "30m"
    update = "40m"
  }
}
