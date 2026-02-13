module "efs" {
  source             = "terraform-aws-modules/efs/aws"
  version            = "1.0.0"
  name               = "my-efs"
  encrypted          = true
  creation_token     = "my-product"
  performance_mode   = "generalPurpose"
  throughput_mode    = "bursting"
  lifecycle_policy   = "AFTER_30_DAYS"
  provisioned_throughput_in_mibps = 0
  enabled            = true

  mount_targets = {
    ap-south-1a = {
      subnet_id = "subnet-12345678"
    }
    ap-south-1b = {
      subnet_id = "subnet-87654321"
    }
  }

  security_group_description = "EFS security group"

  security_group_rules = [
    {
      cidr_blocks = ["10.0.0.0/8"]
    }
  ]
}