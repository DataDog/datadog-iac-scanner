resource "aws_db_instance" "positive1" {
  instance_class       = "db.t2.micro"
  auto_minor_version_upgrade = var.enabled_auto_minor_update ? true : false
}
