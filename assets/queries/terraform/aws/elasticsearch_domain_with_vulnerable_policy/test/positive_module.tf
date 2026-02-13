module "elasticsearch_domain_test" {
  source     = "terraform-aws-modules/elasticsearch/aws"
  version    = "2.2.0"
  domain_name           = "test-domain"
  elasticsearch_version = "2.3"

  cluster_config = {
    instance_type = "t2.small.elasticsearch"
  }

  ebs_options = {
    ebs_enabled = true
    volume_size = 10
  }

  access_policies = <<POLICIES
{
  "Version": "2012-10-17",
  "Statement": {
    "Action": "es:*",
    "Effect": "Allow",
    "Principal": {
      "AWS": "*"
    }
  }
}
POLICIES

  encrypt_at_rest = {
    enabled = true
  }
}