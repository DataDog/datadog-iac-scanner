module "sagemaker_endpoint" {
  source = "github.com/SebastianUA/terraform-aws-sagemaker"
  version = "~> 2.0"

  endpoint_config {
    name         = "my-endpoint-configuration"
    instance_type = "ml.t2.medium"
    model_name     = "my-model"
    variant_name   = "variant-1"
    kms_key_arn    = "arn:aws:kms:us-west-2:123456789098:key/xxxxxx-yy-zz"
  }

  tags = {
    Environment = "Private"
  }
}
