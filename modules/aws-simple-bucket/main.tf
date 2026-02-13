resource "aws_s3_bucket" "bucket" {
  bucket = var.bucket_name
  versioning = var.versioning_config

  tags = {
    "terraform.managed" = "true"
  }
}
