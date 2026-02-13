resource "aws_neptune_cluster_snapshot" "bad_example" {
  db_cluster_identifier          = "example-cluster"
  db_cluster_snapshot_identifier = "example-snapshot"
  storage_encrypted              = false # ❌ Neptune snapshot encryption is disabled
}
