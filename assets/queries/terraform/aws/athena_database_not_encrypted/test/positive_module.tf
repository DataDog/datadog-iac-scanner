module "athena_database" {
  source  = "cloudposse/athena/aws"
  version = "~> 2.0"

  name   = "my_athena_db"
  bucket = "my_athena_bucket"

  force_destroy = true
}
