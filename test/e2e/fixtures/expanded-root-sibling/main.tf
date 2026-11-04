resource "aws_s3_bucket" "plain" {
  bucket = "plain"
}

resource "aws_s3_bucket" "each" {
  for_each = toset(["a", "b"])
  bucket   = each.key
}
