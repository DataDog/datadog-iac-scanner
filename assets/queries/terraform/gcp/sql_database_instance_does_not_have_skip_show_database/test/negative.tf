resource "google_sql_database_instance" "good_example" {
  name             = "good-instance"
  database_version = "MYSQL_8"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-13312"
    database_flags {
      name  = "skip_show_database"
      value = "on" # This flag is present as required
    }
    database_flags {
      name  = "cross db ownership chaining"
      value = "on"
    }
  }
}
