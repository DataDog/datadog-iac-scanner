resource "aws_dms_endpoint" "bad_example_source" {
  endpoint_id   = "example-source"
  endpoint_type = "source"
  engine_name   = "mysql"
  ssl_mode      = "none" # ❌ SSL is disabled for a non-exempt source endpoint
}

resource "aws_dms_endpoint" "bad_example_target" {
  endpoint_id   = "example-target"
  endpoint_type = "target"
  engine_name   = "postgres"
  ssl_mode      = "none" # ❌ SSL is disabled for a non-exempt target endpoint
}
