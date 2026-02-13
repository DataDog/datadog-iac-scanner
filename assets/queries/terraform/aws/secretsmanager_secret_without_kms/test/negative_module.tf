module "complete" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "5.30.1"

  create_role             = true
  role_name               = "complete-example"
  role_requires_mfa       = true
  role_description        = "My awesome role"
  role_permissions_boundary_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  custom_role_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
  ]
  role_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
  ]

  tags = {
    Role = "role"
  }
  kms_key_id = aws_kms_key.example.arn
}
