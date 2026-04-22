resource "aws_s3_bucket_policy" "cross_file_policy" {
  bucket = aws_s3_bucket.cross_file_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.cross_file_bucket.arn}/*"
      }
    ]
  })
}
