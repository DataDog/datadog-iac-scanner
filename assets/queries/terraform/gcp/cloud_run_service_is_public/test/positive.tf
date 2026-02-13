# Failing Terraform Example for IAM Member
resource "google_cloud_run_service_iam_member" "bad_example_member" {
  service = "my-cloud-run-service"
  member  = "allUsers" # ❌ Public principal
  role    = "roles/run.invoker"
}

# Failing Terraform Example for IAM Binding
resource "google_cloud_run_service_iam_binding" "bad_example_binding" {
  service = "my-cloud-run-service"
  members = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
  role    = "roles/run.invoker"
}
