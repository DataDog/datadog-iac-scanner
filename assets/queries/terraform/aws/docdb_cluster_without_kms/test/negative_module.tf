module "cluster" {
  source  = "terraform-aws-modules/docdb/aws"
  version = "~> 1.0"

  identifier    = "democlustor"
  cluster_size  = 2
  engine_version = "3.6.0"
  instance_class = "db.r5.large"
  admin_password = "Mustbe8-characters"
  kms_key_id     = "arn:aws:kms:us-west-2:xxxxxxxxxxxxx:key/xxxxxxxxxxxx"
  vpc_id         = "vpc-4e00c123"

  preferred_backup_window = "07:00-09:00"
  preferred_maintenance_window = "Mon:00:00-Mon:03:00"

  tags = {
    Owner       = "user"
    Environment = "dev"
  }
}