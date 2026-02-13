module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "3.7.0"

  bucket = "my-s3-bucket"
  acl    = "private"

  versioning = {
    enabled = true
  }

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "default_sns_policy",
  "Statement": [
    {
      "Sid": "default-statement-id",
      "Effect": "Allow",
      "Action": [
        "SNS:Publish"
      ],
      "Resource": "${aws_sns_topic.example.arn}",
      "Condition": {
        "ArnEquals": {
          "AWS": "${aws_sns_topic.example.arn}"
        }
      },
      "Principal": {
        "AWS": "010:role/test"
      }
    }
  ]
}
POLICY

}