module "dms_instance" {
  source = "terraform-aws-modules/dms/aws"
  version = "~> 1.0"

  identifier = "test-dms-instance"
  instance_class = "dms.t2.micro"
  allocated_storage = 8
  publicly_accessible = true

  apply_immediately = true
}