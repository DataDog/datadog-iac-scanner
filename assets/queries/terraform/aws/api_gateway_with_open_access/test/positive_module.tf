module "api_gateway_method" {
  source          = "terraform-aws-modules/apigateway-v2/aws"
  version         = "3.0.0"

  name            = "my-apigateway"
  description     = "My awesome HTTP API Gateway"
  protocol_type   = "HTTP"

  custom_domain {
    domain_name = "api.${module.acm.acm_domain_name}"
    certificate_arn = module.acm.acm_certificate_arn

    endpoint_configuration = "REGIONAL"
    security_policy        = "TLS_1_2"
    stage                 = "*"
  }

  cors_configuration {
    allow_headers = ["authorization", "Content-Type", "X-Amz-Date", "X-Api-Key", "X-Amz-Security-Token"]
    allow_methods = ["OPTIONS", "GET", "POST", "PUT", "PATCH", "DELETE"]
    allow_origins = ["*"]
  }
  
  target      = "integrations"
  authorization        = "NONE"
  http_method          = "GET"
}