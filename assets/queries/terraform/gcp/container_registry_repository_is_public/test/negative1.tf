# Passing IAM Member Example
resource "google_storage_bucket_iam_member" "good_example_member" {
  bucket = "example-bucket"
  member = "user:someone@example.com" # ✅ Non-public principal
  role   = "roles/storage.objectViewer"
}
