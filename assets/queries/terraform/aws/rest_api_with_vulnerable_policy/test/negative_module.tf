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
        "Action": "execute-api:Invoke",
        "Resource": "execute-api:/*/*/*",
        "Condition": {
          "IpAddress": {
            "aws:SourceIp": [
              "1.2.3.4/32",
              "4.5.6.7/32"
            ]
          }
        }
      }
    ]
  }
EOS
}