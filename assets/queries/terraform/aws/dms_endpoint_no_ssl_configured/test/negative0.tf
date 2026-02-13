resource "aws_dms_endpoint" "good_example_source" {
  endpoint_id   = "example-source"
  endpoint_type = "source"
  engine_name   = "mysql"
  ssl_mode      = "require" # ✅ SSL is enabled
}

resource "aws_dms_endpoint" "good_example_target" {
  endpoint_id   = "example-target"
  endpoint_type = "target"
  engine_name   = "postgres"
  ssl_mode      = "require" # ✅ SSL is enabled
}