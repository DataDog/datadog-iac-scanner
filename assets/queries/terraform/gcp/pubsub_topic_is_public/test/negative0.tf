# IAM Member compliant
resource "google_pubsub_topic_iam_member" "good_example_member" {
  topic  = "example-topic"
  member = "user:someone@example.com" # ✅ Non-public principal
  role   = "roles/pubsub.publisher"
}
