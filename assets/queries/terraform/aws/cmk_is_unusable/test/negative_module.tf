module "kms" {
  source                  = "terraform-aws-modules/kms/aws"
  version                 = "1.3.0"
  description             = "KMS key for hcp-vault"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  alias                   = "alias/hcp-vault"
  policy                  = data.aws_iam_policy_document.hcp.json
  deletion_window_in_days = 7
}