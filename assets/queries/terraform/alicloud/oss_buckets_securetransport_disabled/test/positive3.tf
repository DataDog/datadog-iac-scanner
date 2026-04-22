resource "alicloud_oss_bucket" "multi_statement" {
  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": ["*"],
      "Action": ["oss:*"],
      "Resource": ["acs:oss:*:*:bucket/*"],
      "Condition": {
        "Bool": {
          "acs:SecureTransport": "true"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": ["*"],
      "Action": ["oss:GetObject"],
      "Resource": ["acs:oss:*:*:bucket/*"],
      "Condition": {
        "Bool": {
          "acs:SecureTransport": "false"
        }
      }
    }
  ]
}
POLICY
}
