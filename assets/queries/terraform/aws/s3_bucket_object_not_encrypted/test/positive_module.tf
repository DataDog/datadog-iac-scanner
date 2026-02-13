module "s3_object" {
  source  = "terraform-aws-modules/s3-bucket/aws//modules/object"
  version = "2.3.0"

  bucket  = aws_s3_bucket.example.id
  key     = "my_app.conf"
  content = "Hello, world!"
}
