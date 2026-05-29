provider "aws" { region = "us-east-1" }
resource "aws_s3_bucket" "prod" {
  bucket = "prod-bucket"
  tags   = { Env = "prod" }  # no Team tag
}
