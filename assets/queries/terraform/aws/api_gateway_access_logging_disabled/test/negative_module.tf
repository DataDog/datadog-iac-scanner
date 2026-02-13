module "apigatewayv2" {
  source  = "terraform-aws-modules/apigateway-v2/aws"
  version = "~> 2.0"

  name          = "example"
  description   = "HTTP API Gateway"
  protocol_type = "HTTP"

  cors_configuration = {
    allow_credentials = false
    allow_headers     = ["*"]
    allow_methods     = ["GET", "POST", "OPTIONS"]
    allow_origins     = ["*"]
    expose_headers    = ["*"]
    max_age           = 300
  }

  default_route_settings = {
    detailed_metrics_enabled = true
    throttling_burst_limit  = 10
    throttling_rate_limit   = 20
    "logging_level"         = "ERROR"
  }

  target = aws_lambda_function.example.arn

  access_log_settings = {
    destination_arn = module.log_group.cloudwatch_log_group_arn
    format          = "$context.identity.sourceIp $context.identity.caller $context.identity.user [$context.requestTime] \"$context.httpMethod $context.resourcePath $context.protocol\" $context.status $context.requestLength $context.responseLength $context.requestId"
  }

  depends_on = [aws_cloudwatch_log_group.example]
}