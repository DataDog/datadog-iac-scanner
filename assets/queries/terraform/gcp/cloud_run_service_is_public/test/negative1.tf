# Passing Terraform Example for IAM Binding
resource "google_cloud_run_service_iam_binding" "good_example_binding" {
  service = "my-cloud-run-service"
  members = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
  role    = "roles/run.invoker"
}
