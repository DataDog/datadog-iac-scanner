module "elasticsearch" {
  source = "terraform-aws-modules/elasticsearch/aws"

  domain_name           = "test-domain"
  elasticsearch_version = "2.3"

  cluster_config = {
    instance_type = "m4.large.elasticsearch"
  }

  ebs_options = {
    ebs_enabled = true
    volume_size = 10
  }

  access_policies = <<CONFIG
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "es:*",
      "Principal": "*",
      "Effect": "Allow",
      "Resource": "arn:aws:es:eu-west-1:123456789012:domain/test-domain/*"
    }
  ]
}
CONFIG

  snapshot_options = {
    automated_snapshot_start_hour = 23
  }

  tags = {
    Domain = "TestDomain"
  }
}