// dd_terraform_vars: env/prod.tfvars
variable "acl" {}

resource "aws_s3_bucket" "b" {
  acl = var.acl
}
