module "elasticache_redis" {
  source = "terraform-aws-modules/elasticache/aws"
  version = "0.49.0"

  namespace     = "eg"
  stage         = "prod"
  name          = "redis"
  instance_type = "cache.t2.micro"
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]
  cluster_size  = 2

  description     = "Elasticache redis cluster for the foo service"
  alarm_actions   = ["${aws_kms_key.example.arn}"]
  ok_actions      = ["${aws_kms_key.example.arn}"]

  subnets         = ["subnet-a4dc27fb", "subnet-b7c9c1c5", "subnet-c9345686"]
  vpc_id          = "vpc-xxxxxx"
  allowed_cidr    = "10.10.10.10/32"
  region          = "us-west-2"
}
