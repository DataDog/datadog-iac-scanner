module "api_gateway_method" {
  source = "terraform-aws-modules/apigateway-v2/aws"

  name          = "my-apigateway"
  description   = "HTTP API Gateway"
  protocol_type = "HTTP"

  cors_configuration = {
    allow_credentials = true
    allow_headers     = ["authorization", "content-type", "x-api-key"]
    allow_methods     = ["GET", "POST", "OPTIONS"]
    allow_origins     = ["*"]
    expose_headers    = ["x-api-key"]
    max_age           = 600
  }

  target = "1.1.1.1"
  api_key_required = true

  access_log_settings = {
    destination_arn = "test"
    format = "test"
  }

  depends_on = [
    aws_cloudwatch_log_group.example
  ]
}