module "bucket" {
    source = "./nested_module"
    auto_minor_version_upgrade = var.auto_minor_version_upgrade
}
