module "athena" {
  source = "cloudposse/athena/aws"
  name = "my_athena_wg"
  named_queries = ""
  databases = ""
  data_catalogs = ""

  enforce_workgroup_configuration    = true
  publish_cloudwatch_metrics_enabled = true
  bytes_scanned_cutoff_per_query     = 10000000

  s3_output_path = "s3://query-results-location/"

  workgroup_encryption_option = "SSE_S3"
}
