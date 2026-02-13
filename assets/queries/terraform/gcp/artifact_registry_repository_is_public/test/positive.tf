# IAM Member violation
resource "google_artifact_registry_repository_iam_member" "bad_example_member" {
  repository = "example-repo"
  member     = "allUsers" # ❌ Public principal
  role       = "roles/artifactregistry.reader"
}

# IAM Binding violation
resource "google_artifact_registry_repository_iam_binding" "bad_example_binding" {
  repository = "example-repo"
  members    = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
  role       = "roles/artifactregistry.admin"
}
