module "default_driver" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "7.4.0"

  name           = "cluster"
  engine         = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.03.2"

  instance_type         = "db.r5.large"
  instances_database_name  = "test"
  instances_database_user  = "test"
  instances_database_password  = "testpassword"
  instances_database_port  = "3306"
  storage_encrypted = true

  vpc_id                    = "vpc-12345678"
  subnets                   = ["subnet-12345678"]
  allowed_security_groups   = ["sg-12345678"]
}