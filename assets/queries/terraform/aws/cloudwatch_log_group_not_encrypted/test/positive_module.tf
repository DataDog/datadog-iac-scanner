module "cloudwatch_log_group" {
  source = "terraform-aws-modules/cloudwatch/aws"
  version = "4.0.1"

  name              = "app1"
  retention_in_days = 7
}
