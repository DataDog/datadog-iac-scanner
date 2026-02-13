module "redshift" {
  source = "terraform-aws-modules/redshift/aws"
  version = "~> 3.0"

  cluster_identifier = "redshift-cluster-demo"
  database_name      = "demodb"
  master_username    = "adminuser"
  master_password    = "AdminUser12345"

  logging {
    enable = true
    bucket_name = "foo"
  }
}