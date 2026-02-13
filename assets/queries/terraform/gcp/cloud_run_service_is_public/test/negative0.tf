# Passing Terraform Example for IAM Member
resource "google_cloud_run_service_iam_member" "good_example_member" {
  service = "my-cloud-run-service"
  member  = "user:someone@example.com" # ✅ Non-public principal
  role    = "roles/run.invoker"
}

