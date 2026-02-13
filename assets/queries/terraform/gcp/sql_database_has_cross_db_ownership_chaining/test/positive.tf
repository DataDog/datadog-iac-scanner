resource "google_sql_database_instance" "bad_example" {
  name             = "bad-instance"
  database_version = "SQLSERVER_2019_STANDARD"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-13312"
    database_flags {
      name  = "cross db ownership chaining"
      value = "on"
    }
  }
}
