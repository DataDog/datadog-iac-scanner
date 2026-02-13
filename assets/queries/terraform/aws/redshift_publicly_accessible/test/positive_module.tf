module "redshift" {
  source  = "terraform-aws-modules/redshift/aws"
  version = "~> 3.0"

  cluster_identifier = "redshift-cluster-demo"
  database_name      = "demodb"
  master_username    = "adminuser"
  master_password    = "UserPass123"
  node_type          = "dc2.large"
  publicly_accessible = true

  cluster_type = "single-node"

  # enhanced_vpc_routing = true

  # This is to avoid "trying to delete resource repeatedly" issue with this resource
  skip_final_snapshot = true
  iam_roles           = []

  tags = {
    Owner       = "user"
    Environment = "dev"
  }

  depends_on = [
    aws_iam_role_policy_attachment.redshift-access,
    aws_iam_role_policy_attachment.redshift-access2,
  ]
}