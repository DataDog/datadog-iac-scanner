module "db" {
  source  = "terraform-aws-modules/rds/aws"

  identifier = "demodb"
  auto_minor_version_upgrade = var.enabled_auto_minor_update
}
