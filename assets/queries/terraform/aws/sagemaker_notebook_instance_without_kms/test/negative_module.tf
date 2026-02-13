module "notebook" {
  source = "github.com/SebastianUA/terraform-aws-sagemaker"
  version = "~> 2.0"

  name      = "notebook"
  role_arn  = module.notebook_role.iam_role_arn
  subnet_id = module.vpc.private_subnets[0]

  instance_type = "ml.t2.medium"
  kms_key_id        = aws_kms_key.this.id
  root_access = "Enabled"

  policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
  ]

  lifecycle_config {
    jupyter_server_app_settings_lifecycle_config_arn = aws_sagemaker_app_image_config.jupyter.arn
  }

  vpc_security_group_ids = [
    module.security_group.security_group_id
  ]

  tags = {
    Owner   = "user"
    Project = "foo"
  }

  depends_on = [module.vpc]

  instance_metadata_service_configuration {
    minimum_instance_metadata_service_version = "2"
  }
}
