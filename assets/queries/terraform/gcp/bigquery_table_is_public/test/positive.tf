# IAM Member violation
resource "google_bigquery_table_iam_member" "bad_example_member" {
  table  = "example_table"
  member = "allUsers" # ❌ Public principal
  role   = "roles/bigquery.dataViewer"
}

# IAM Binding violation
resource "google_bigquery_table_iam_binding" "bad_example_binding" {
  table   = "example_table"
  members = ["allAuthenticatedUsers", "user:someone@example.com"] # ❌ Contains public principal
  role    = "roles/bigquery.dataViewer"
}
