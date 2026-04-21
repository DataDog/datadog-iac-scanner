resource "aws_s3_bucket_policy" "jsonencoded" {
  bucket = aws_s3_bucket.example.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = "*"
        Resource  = "arn:aws:s3:::example-bucket/*"
      }
    ]
  })
}
