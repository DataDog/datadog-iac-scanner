module "neptune" {
  source = "terraform-aws-modules/neptune/aws"

  cluster_name = "example"

  engine_version = "1.0.2.2"

  instance_class = "db.r4.large"
  instance_count = 2

  apply_immediately   = true
  skip_final_snapshot = true

  vpc_id     = "vpc-abcde012"
  subnets    = ["subnet-abcde012", "subnet-abcde123", "subnet-abcde234"]
  name       = "neptune"
  namespace  = "neptune"
  stage      = "dev"
}