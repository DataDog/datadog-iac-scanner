resource "aws_s3_bucket_acl" "good_example" {
  bucket = aws_s3_bucket.example.id

  access_control_policy {
    grant {
      grantee {
        type = "CanonicalUser"
        id   = "1234567890abcdef1234567890abcdef12345678" # ✅ Restricted access
      }
      permission = "READ"
    }
    owner {
      id = aws_s3_bucket.example.owner_id
    }
  }
}
