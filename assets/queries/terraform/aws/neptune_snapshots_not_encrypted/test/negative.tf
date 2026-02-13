resource "aws_neptune_cluster_snapshot" "good_example" {
  db_cluster_identifier          = "example-cluster"
  db_cluster_snapshot_identifier = "example-snapshot"
  storage_encrypted              = true # ✅ Neptune snapshot encryption is enabled
}
