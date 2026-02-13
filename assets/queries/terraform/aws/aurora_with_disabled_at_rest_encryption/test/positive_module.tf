module "rds_cluster" {
  source = "terraform-aws-modules/rds-aurora/aws"
  version = "~> 7.0"

  name            = "aurora-example"
  engine          = "aurora-mysql"
  engine_version  = "5.7.12"
  instance_type   = "r5.large"
  storage_encrypted = false

  username = "root"
  password = "123SecurePassword123"
  port     = "3306"

  vpc_id  = "vpc-12345678"
  subnets = ["subnet-12345678", "subnet-87654321"]

  allowed_cidr_blocks = ["10.20.0.0/16"]

  monitoring_interval = 10
  instance_monitoring_interval = 60

  apply_immediately   = true
  skip_final_snapshot = true

  # Database Deletion Protection
  # deletion_protection = true

  tags = {
    Owner       = "user"
    Environment = "dev"
  }
}