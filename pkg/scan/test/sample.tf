resource "aws_s3_bucket" "scan_smoke" {
  bucket = "scan-smoke-bucket"
  acl    = "authenticated-read"
}
