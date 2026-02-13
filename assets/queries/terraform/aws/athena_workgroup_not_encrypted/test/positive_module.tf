module "athena" {
  source = "cloudposse/athena/aws"
  name = "my_athena_wg"
  named_queries = ""
  databases = ""
  data_catalogs = ""

  publish_cloudwatch_metrics_enabled = true
  bytes_scanned_cutoff_per_query     = 10000000
}
