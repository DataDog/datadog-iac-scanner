resource "aws_s3_bucket" "untagged" {
  bucket = "determinism-bucket"

  tags = {
    Environment = "Dev"
  }
}
