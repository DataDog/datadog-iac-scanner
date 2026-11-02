module "m" {
  source = "../../modules/m"
}

resource "aws_s3_bucket_versioning" "shared" {
  bucket = "shared"
}
