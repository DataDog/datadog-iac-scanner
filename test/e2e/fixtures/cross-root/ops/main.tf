resource "aws_s3_bucket_versioning" "prod" {
  bucket = "acme-versioned-elsewhere"
  versioning_configuration {
    status = "Enabled"
  }
}
