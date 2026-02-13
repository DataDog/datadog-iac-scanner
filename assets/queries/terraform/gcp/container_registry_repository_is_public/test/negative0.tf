# Passing IAM Binding Example
resource "google_storage_bucket_iam_binding" "good_example_binding" {
  bucket  = "example-bucket"
  members = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
  role    = "roles/storage.objectViewer"
}
