module "detector" {
  source  = "terraform-aws-modules/guardduty/aws//modules/detector"
  version = "~> 3.0"

  enable = true
}