module "api_gateway_custom_domain" {
  source   = "terraform-aws-modules/apigateway-v2/aws"
  version  = "3.0.2"
  security_policy = "TLS_1_0"
  description          = "My awesome HTTP API"
  create_api_domain_name = true
  domain_name = "api.${module.acm.acm_certificate_domain}"

  domain_name_certificate_arn = module.acm.acm_certificate_arn

  cors_configuration = {
    allow_credentials = false
    allow_headers     = ["date", "keep-alive"]
    allow_methods     = ["PUT", "POST"]
    allow_origins     = ["*"]
    expose_headers    = ["keep-alive"]
    max_age           = 5
  }

  integrations = {
    "ANY /{proxy+}" = {
      lambda_arn             = module.lambda_function.lambda_function_arn
      payload_format_version = "2.0"
      timeout_milliseconds  = 12000
      }
    }
}