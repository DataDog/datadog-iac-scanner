# IAM Binding compliant
resource "google_pubsub_topic_iam_binding" "good_example_binding" {
  topic   = "example-topic"
  members = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
  role    = "roles/pubsub.subscriber"
}
