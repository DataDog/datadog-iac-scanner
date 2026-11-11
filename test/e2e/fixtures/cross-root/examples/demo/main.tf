resource "aws_s3_bucket_versioning" "planted" {
  bucket = "acme-planted-in-example"
  versioning_configuration {
    status = "Enabled"
  }
}
