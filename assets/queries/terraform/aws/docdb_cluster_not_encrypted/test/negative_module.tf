module "cluster" {
  source = "terraform-aws-modules/docdb/aws"
  version = "~> 1.0"

  cluster_name  = "docdb-demo"
  cluster_size  = 2
  pgbouncer_size = 0
  instance_name = "docdb-demo"
  admin_password = "Mustbe8-32characters"
  vpc_id = "vpc-c04451a6"
  subnets = ["subnet-a8a540ee", "subnet-7b1b5109", "subnet-fb0a218b"]
  storage_encrypted = true

  tags = {
    Owner       = "user"
    Environment = "dev"
  }
}