resource "aws_s3_bucket" "this" {
  bucket = "my_tf_test_bucket"
  tags = {
    Name = "My bucket"
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # When used directly as a Cloudfront origin.
      Effect = "Allow"
      Action = "s3:GetObject"
      Principal = {
        Service = "cloudfront.amazonaws.com"
      }
      Resource = [
        "${aws_s3_bucket.this.arn}/*",
      ]
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.this.arn
        }
      }
      },
      {
        # Admin access for policy updates, etc.
        Effect = "Allow"
        Action = "s3:*"
        Principal = {
          AWS = [
            data.aws_caller_identity.current.id,
          ]
        }
        Resource = [
          "${aws_s3_bucket.this.arn}/*",
        ]
      },
      {
        # Delegate access to the access point.
        Effect = "Allow"
        Action = "*"
        Principal = {
          AWS = [
            "*"
          ]
        }
        Resource = [
          aws_s3_bucket.this.arn,
          "${aws_s3_bucket.this.arn}/*",
        ]
        Condition = {
          "StringEquals" = {
            "s3:DataAccessPointAccount" = data.aws_caller_identity.current.account_id
          }
        }
    }]
  })
}
