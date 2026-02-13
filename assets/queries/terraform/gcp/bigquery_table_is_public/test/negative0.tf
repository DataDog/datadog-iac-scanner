# IAM Member compliant
resource "google_bigquery_table_iam_member" "good_example_member" {
  table  = "example_table"
  member = "user:someone@example.com" # ✅ Non-public principal
  role   = "roles/bigquery.dataViewer"
}
