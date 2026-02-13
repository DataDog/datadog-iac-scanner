# Failing IAM Member Example
resource "google_storage_bucket_iam_member" "bad_example_member" {
  bucket = "example-bucket"
  member = "allUsers" # ❌ Public principal
  role   = "roles/storage.objectViewer"
}

# Failing IAM Binding Example
resource "google_storage_bucket_iam_binding" "bad_example_binding" {
  bucket  = "example-bucket"
  members = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
  role    = "roles/storage.objectViewer"
}
