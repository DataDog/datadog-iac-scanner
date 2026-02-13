resource "aws_dms_endpoint" "good_example_exempt_source" {
  endpoint_id   = "example-source-s3"
  endpoint_type = "source"
  engine_name   = "s3"
  ssl_mode      = "none" # ✅ S3 source is exempt
}

resource "aws_dms_endpoint" "good_example_exempt_target" {
  endpoint_id   = "example-target-kinesis"
  endpoint_type = "target"
  engine_name   = "kinesis"
  ssl_mode      = "none" # ✅ Kinesis target is exempt
}
