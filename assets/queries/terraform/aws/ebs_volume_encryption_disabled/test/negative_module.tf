module "ebs_volume" {
  source  = "terraform-aws-modules/ebs/aws"
  version = "~> 3.0"

  # Use data resources to generate a list
  create        = true
  availability_zone = "eu-west-1a"
  size = 1
  type = "gp3"

  # Encryption at rest by default
  encrypted = true
}