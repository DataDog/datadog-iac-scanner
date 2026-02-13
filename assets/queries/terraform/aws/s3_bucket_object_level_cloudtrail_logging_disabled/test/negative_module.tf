module "cloudtrail" {
  source = "terraform-aws-modules/cloudtrail/aws"
  version = "3.1.0"

  name = "cloudtrail"

  s3_bucket_server_side_encryption_enabled = true
  enable_log_file_validation               = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}