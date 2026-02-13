# IAM Binding compliant
resource "google_bigquery_table_iam_binding" "good_example_binding" {
  table   = "example_table"
  members = ["user:someone@example.com", "group:admins@example.com"] # ✅ No public principals
  role    = "roles/bigquery.dataViewer"
}
