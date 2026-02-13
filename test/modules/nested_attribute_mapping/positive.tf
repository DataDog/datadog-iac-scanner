module "bucket" {
    source = "./module"
    bucket_name = "aws bucket"
    enabled_versioning = false
}
