module "clusters" {
  source  = "terraform-aws-modules/redshift/aws"
  version = "~> 2.0"

  cluster_identifier = "redshift-cluster-1"
  database_name      = "example"

  master_username = "foo"
  master_password = "Mustbe8-characters"

  node_type        = "dc1.large"
  number_of_nodes  = 1
  encrypted        = true
  cluster_subnet_group_name = "subnet"

  enhanced_vpc_routing = false

  allowed_security_groups = ["12345", "67890"]
  apply_immediately       = true
}