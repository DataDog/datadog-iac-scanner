# IAM Member compliant
resource "google_artifact_registry_repository_iam_member" "good_example_member" {
  repository = "example-repo"
  member     = "user:someone@example.com" # ✅ Non-public principal
  role       = "roles/artifactregistry.reader"
}
