module "apigateway_stage" {
  source  = "terraform-aws-modules/apigateway-v2/aws"
  version = "~> 2.0"

  name          = "example"
  description   = "HTTP API Gateway"
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = ["*"]
    allow_methods = ["POST", "OPTIONS"]
    allow_origins = ["*"]
  }

  target_arn = "arn:aws:lambda:eu-west-1:1:function:example"

  access_log_settings {
    destination_arn = "arn:aws:logs:eu-west-1:1:log-group:apigateway-access-logs"
    format          = "$context.identity.sourceIp $context.identity.caller $context.identity.user [$context.requestTime] \"$context.httpMethod $context.resourcePath $context.protocol\" $context.status $context.requestLength $context.responseLength $context.requestId"
  }
}