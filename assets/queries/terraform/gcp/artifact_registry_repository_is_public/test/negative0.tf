
# IAM Binding compliant
resource "google_artifact_registry_repository_iam_binding" "good_example_binding" {
  repository = "example-repo"
  members    = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
  role       = "roles/artifactregistry.admin"
}
