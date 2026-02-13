module "glue_policy" {
  source = "terraform-aws-modules/glue/aws"
  version = "~> 2.0"

  data_catalog_encryption_settings = {
    "data_catalog_encryption_settings" : {
      "connection_password_encryption" : {
        "aws_kms_key_id" : "string",
        "return_connection_password_encrypted" : "bool"
      },
      "encryption_at_rest" : {
        "catalog_encryption_mode" : "string",
        "sse_aws_kms_key_id" : "string"
      }
    }
  }

  workflow_name = "foo"
  description   = "bar"
  max_concurrent_runs = 5

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "glue:GetTable",
            "Resource": "*"
        }
    ]
}
POLICY

}