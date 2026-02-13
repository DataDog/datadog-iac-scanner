module "ebs_encryption" {
  source  = "terraform-aws-modules/ebs-encryption/aws"
  version = "~> 1.0"

  enabled = false
}