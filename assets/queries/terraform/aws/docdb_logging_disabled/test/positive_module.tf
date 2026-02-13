module "db" {
  source  = "terraform-aws-modules/docdb/aws"
  version = "~> 1.0"

  identifier = "docdb-cluster"

  cluster_size       = 2
  engine_version     = "3.6.0"
  instance_class     = "db.r5.large"
  admin_password     = "DocDB@1234567890"
  vpc_security_group_ids = [aws_security_group.default.id]
  db_subnet_group_name   = aws_db_subnet_group.default.id

  tags = {
    Owner       = "user"
    Environment = "dev"
  }

  enabled_cloudwatch_logs_exports = ["audit"]

}