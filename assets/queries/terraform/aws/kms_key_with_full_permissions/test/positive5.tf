resource "aws_kms_key" "jsonencoded" {
  description             = "KMS jsonencoded"
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "JsonEncodedVulnerable"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["kms:*"]
        Resource  = "*"
      }
    ]
  })
}
