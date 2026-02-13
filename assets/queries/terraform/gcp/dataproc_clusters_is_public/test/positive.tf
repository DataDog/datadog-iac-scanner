# Positive test case# Failing IAM Member example
resource "google_dataproc_cluster_iam_member" "bad_member" {
  name   = "bad-dataproc-member"
  member = "allUsers" # ❌ Public principal
}

# Failing IAM Binding example
resource "google_dataproc_cluster_iam_binding" "bad_binding" {
  name    = "bad-dataproc-binding"
  members = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
}
