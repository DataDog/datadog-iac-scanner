# Passing IAM Member example
resource "google_dataproc_cluster_iam_member" "good_member" {
  name   = "good-dataproc-member"
  member = "user:someone@example.com" # ✅ Non-public principal
}
