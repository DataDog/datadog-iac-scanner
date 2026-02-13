resource "google_service_account_key" "bad_key" {
  service_account_id = "projects/my-project/serviceAccounts/my-service-account"
}
