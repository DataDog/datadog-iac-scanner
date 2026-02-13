# IAM Member violation
resource "google_pubsub_topic_iam_member" "bad_example_member" {
  topic  = "example-topic"
  member = "allUsers" # ❌ Public principal
  role   = "roles/pubsub.publisher"
}

# IAM Binding violation
resource "google_pubsub_topic_iam_binding" "bad_example_binding" {
  topic   = "example-topic"
  members = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
  role    = "roles/pubsub.subscriber"
}
