module "cloudtrail" {
  source = "terraform-aws-modules/cloudtrail/aws"
  version = "3.0.0"

  enable_logging = true
  s3_key_prefix  = "prefix"
  is_organization_trail = true

  sns_topic_name = "loudtrails"

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  event_selector = {
    read_write_type           = "All"
    include_management_events = true

    data_resource = {
      type = "AWS::S3::Object"
      values = [
        "arn:aws:s3:::",
      ]
    }
  }
}