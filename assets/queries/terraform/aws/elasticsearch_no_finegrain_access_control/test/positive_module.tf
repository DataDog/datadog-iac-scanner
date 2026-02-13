module "os" {
  source = "terraform-aws-modules/opensearch/aws"
  version = "1.7.0"
  # insert the 9 required variables here
  domain_name           = "example-opensearch"
  subnet_ids            = ["subnet-1234foobar", "subnet-5678foobar"]
  vpc_id                = "vpc-12345678"
  instance_type         = "t3.small.search"
  master_instance_type  = "t3.small.search"
  create_service_role   = true
  ebs_enabled           = true
  ebs_volume_size       = 10

  advanced_security_options {
    enabled = false
    internal_user_database_enabled = true
    master_user_options {
      master_user_arn      = "arn:aws:iam::123456789012:user/opensearch"
      master_user_name     = null
      master_user_password = null
    }
  }

    vpc_options {
    security_group_ids = ["sg-12345678"]
  }
}