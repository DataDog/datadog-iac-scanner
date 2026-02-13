module "api_gateway_resource_policy" {
  source  = "terraform-aws-modules/apigateway-v2/aws"
  version = "~> 2.1"

  name          = "my-apigateway"
  description   = "My awesome API Gateway"
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = ["*"]
    allow_methods = ["*"]
    allow_origins = ["*"]
  }

  policy = <<EOS
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "Stmt1621427439000",
        "Effect": "Allow",
        "Action": "execute-api:*",
        "Principal": "*",
        "Resource": "execute-api:/*/*/*"
      }
    ]
  }
EOS
}