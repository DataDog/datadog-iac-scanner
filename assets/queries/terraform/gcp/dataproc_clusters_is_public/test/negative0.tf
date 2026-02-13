# Passing IAM Binding example
resource "google_dataproc_cluster_iam_binding" "good_binding" {
  name    = "good-dataproc-binding"
  members = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
}
