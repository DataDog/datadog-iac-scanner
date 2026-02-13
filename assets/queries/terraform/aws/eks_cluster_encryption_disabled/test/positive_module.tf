module "eks" {
  source          = "terraform-aws-modules/eks/aws"

  vpc_id = "vpc-1234556abcdef"

}
