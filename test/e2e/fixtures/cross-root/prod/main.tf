resource "aws_s3_bucket" "versioned_elsewhere" {
  bucket = "acme-versioned-elsewhere"
}

resource "aws_s3_bucket" "planted_in_example" {
  bucket = "acme-planted-in-example"
}
