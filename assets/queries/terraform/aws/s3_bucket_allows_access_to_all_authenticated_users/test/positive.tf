resource "aws_s3_bucket_acl" "bad_example" {
  bucket = aws_s3_bucket.example.id

  access_control_policy {
    grant {
      grantee {
        type = "Group"
        uri  = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" # ❌ Allows access to all authenticated users
      }
      permission = "READ"
    }
    owner {
      id = aws_s3_bucket.example.owner_id
    }
  }
}
